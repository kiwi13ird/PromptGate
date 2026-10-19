"""판정 기록의 가린 결과·위치·본문 순번 (2026-10-09). 화면이 원문(prompt)과 나란히 놓고 가린 자리를 그릴 수 있어야 한다."""

from __future__ import annotations

import json
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

import detection_service.pipeline as pipeline
from detection_service import pg_store
from detection_service.decision_log import COLUMNS, DecisionLog
from detection_service.pipeline import preprocess, recorded_masking

RRN = "900101-1234567"


def finding(base, value, entity="KR_RRN", replacement="[KR_RRN]"):
    start = base.index(value)
    return {"entity_type": entity, "start": start, "end": start + len(value), "score": 1.0,
            "policy_action": "mask_full", "replacement": replacement}


def masked(base, value, replacement="[KR_RRN]"):
    return base.replace(value, replacement)


def test_nothing_masked_records_nothing():
    assert recorded_masking({"findings": [], "masked_text": None}, "안녕하세요", None) == (None, None)


def test_prompt_positions_are_kept_and_values_are_not_copied():
    text = f"주민번호 {RRN} 확인"
    row = {"findings": [finding(text, RRN)], "masked_text": masked(text, RRN)}
    after, items = recorded_masking(row, text, None)
    assert after == "주민번호 [KR_RRN] 확인"
    assert items == [{"entity_type": "KR_RRN", "replacement": "[KR_RRN]", "policy_action": "mask_full",
                      "start": 5, "end": 5 + len(RRN)}]
    assert RRN not in json.dumps(items)          # 위치·유형만, 값은 남기지 않는다


@pytest.mark.parametrize("raw", [
    f"이름:   홍길동\t\t주민번호   {RRN}  끝",        # 여러 칸 공백·탭
    f"​주민번호:  {RRN}",                         # 보이지 않는 문자
    f"주민번호 —  {RRN.replace('-', '–')} 끝",           # 대시 표준화(값 안의 – 도 - 로)
    f"  앞 공백\n\n\n\n주민번호 {RRN}",                 # 앞 공백 · 빈 줄 축약
])
def test_file_positions_move_to_recorded_text(raw):
    value = RRN.replace("-", "–") if "–" in raw else RRN
    text = preprocess(raw)
    row = {"findings": [finding(raw, value)], "masked_text": masked(raw, value)}
    after, (item,) = recorded_masking(row, text, raw)
    assert text[item["start"]:item["end"]] == preprocess(value)
    assert after == preprocess(masked(raw, value))
    assert after.count("[KR_RRN]") == 1


def test_position_is_dropped_rather_than_guessed():
    raw = f"주민번호 {RRN}"
    text = preprocess(raw) + " 다른 내용"                 # 기록 원문이 원본과 어긋난 경우를 흉내
    bad = {"entity_type": "KR_RRN", "start": 0, "end": 4, "policy_action": "mask_full", "replacement": "[KR_RRN]"}
    row = {"findings": [bad], "masked_text": "[KR_RRN] " + RRN}
    _, (item,) = recorded_masking(row, "전혀 다른 글자 " + text, raw)
    assert "start" not in item and "end" not in item and item["entity_type"] == "KR_RRN"


def test_two_findings_in_one_cell():
    raw = f"번호  {RRN} / 메일   a.b@example.com"
    text = preprocess(raw)
    row = {"findings": [finding(raw, RRN), finding(raw, "a.b@example.com", "EMAIL_ADDRESS", "[EMAIL_ADDRESS]")],
           "masked_text": raw.replace(RRN, "[KR_RRN]").replace("a.b@example.com", "[EMAIL_ADDRESS]")}
    after, items = recorded_masking(row, text, raw)
    assert [text[i["start"]:i["end"]] for i in items] == [RRN, "a.b@example.com"]
    assert after == "번호 [KR_RRN] / 메일 [EMAIL_ADDRESS]"


# ---------------------------------------------------------------- 기록 줄 · RDS 전송


@pytest.fixture()
def run_logged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log = DecisionLog(tmp_path / "decisions.jsonl")

    def fake_decide(r, text, row, *, signature_text=None, context_label=None):
        base = text if signature_text is None else signature_text
        if RRN in base:
            row.update(decided_by="signature", pii_hits="KR_RRN:1", signature_status="ok",
                       findings=[finding(base, RRN)], masked_text=masked(base, RRN))
            return "mask_full"
        return "allow"

    monkeypatch.setattr(pipeline, "_decide", fake_decide)
    monkeypatch.setattr(pipeline, "read_epoch", lambda r: None)
    monkeypatch.setattr(pipeline, "reference", lambda r, row, epoch: None)

    def run(text, source=None):
        pipeline.run(fakeredis.FakeRedis(), text, request_id="R1", source=source, decision_log=log)
        lines = (tmp_path / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1])
    return run


def test_masked_file_cell_is_recorded_with_block_order(run_logged):
    raw = f"주민번호   {RRN}"
    rec = run_logged(raw, {"service": "ChatGPT", "content_type": "file", "signature_original_offsets": True,
                           "block_order": 7})
    assert list(rec) == list(COLUMNS)
    assert rec["prompt"] == preprocess(raw)
    assert rec["masked_text"] == "주민번호 [KR_RRN]"
    assert rec["prompt"][rec["findings"][0]["start"]:rec["findings"][0]["end"]] == RRN
    assert rec["block_order"] == 7


def test_unmasked_row_leaves_new_columns_empty(run_logged):
    rec = run_logged("오늘 회의록", {"service": "ChatGPT", "content_type": "prompt"})
    assert rec["masked_text"] is None and rec["findings"] is None and rec["block_order"] is None


def test_block_order_must_be_an_integer(run_logged):
    rec = run_logged(f"주민번호 {RRN}", {"content_type": "file", "block_order": "3"})
    assert rec["block_order"] is None


def test_detect_api_accepts_block_order_and_rejects_negative(monkeypatch, tmp_path):
    monkeypatch.setenv("DETECTION_LOG_PATH", str(tmp_path / "logs" / "decisions.jsonl"))
    import detection_service.main as main_module

    fake = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(main_module, "connect_redis", lambda: fake)
    with TestClient(main_module.app) as client:
        ok = client.post("/detect", json={"request_id": "B1", "normalized_text": "회의록",
                                           "source": {"content_type": "file", "block_order": 3}})
        bad = client.post("/detect", json={"request_id": "B2", "normalized_text": "회의록",
                                            "source": {"content_type": "file", "block_order": -1}})
    assert ok.status_code == 200 and bad.status_code == 422
    rec = json.loads((tmp_path / "logs" / "decisions.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert rec["block_order"] == 3


def test_pg_params_follow_insert_columns():
    rec = {c: None for c in COLUMNS} | {"decision_id": "d", "ts": 1.0, "findings": [{"entity_type": "KR_RRN", "start": 1, "end": 3}],
                                        "masked_text": "[KR_RRN]", "block_order": 2}
    params = pg_store.to_params(rec)
    assert len(params) == len(pg_store.INSERT_COLUMNS)
    by_col = dict(zip(pg_store.INSERT_COLUMNS, params))
    assert by_col["masked_text"] == "[KR_RRN]" and by_col["block_order"] == 2
    assert json.loads(by_col["findings"]) == [{"entity_type": "KR_RRN", "start": 1, "end": 3}]
    assert pg_store.to_params({**rec, "findings": None})[pg_store.INSERT_COLUMNS.index("findings")] is None
