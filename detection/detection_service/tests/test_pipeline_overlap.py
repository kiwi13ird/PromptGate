"""겹치는 인식기 적중 병합(명세 §3.4) - /detect에도 적용된다. 겹침이 없으면 응답이 바뀌지 않아야 한다."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import detection_service.pipeline as pipeline
from detection_service import policy_store
from signature import engine
from signature.engine import Hit

from test_main import client  # noqa: F401


def _merge(spec):
    hits = [Hit(t, s, e, sc) for t, s, e, sc, _ in spec]
    return pipeline._merge_overlaps(hits, [a for *_, a in spec])


def test_no_overlap_returns_input_unchanged():
    hits = [Hit("KR_RRN", 0, 14, 0.9), Hit("EMAIL_ADDRESS", 14, 30, 0.9), Hit("KR_PHONE_NUMBER", 40, 53, 0.9)]
    actions = ("MASK_FULL", "ALLOW", "MASK_PARTIAL")
    merged, merged_actions = pipeline._merge_overlaps(hits, actions)
    assert merged == hits and merged_actions == list(actions)        # 맞닿은 0-14, 14-30은 합치지 않는다
    assert all(a is b for a, b in zip(merged, hits))


def test_overlap_takes_union_strongest_action_and_longest_type():
    merged, actions = _merge([("A", 0, 10, 0.5, "ALLOW"), ("B", 5, 20, 0.9, "MASK_FULL"), ("C", 18, 22, 0.7, "MASK_PARTIAL"),
                              ("D", 30, 35, 0.8, "MASK_FULL")])
    assert merged == [Hit("B", 0, 22, 0.9), Hit("D", 30, 35, 0.8)] and actions == ["MASK_FULL", "MASK_FULL"]


def test_block_notify_wins_and_longest_of_that_action_names_it():
    merged, actions = _merge([("X", 2, 6, 0.5, "BLOCK_NOTIFY"), ("Y", 0, 12, 0.9, "MASK_FULL"), ("Z", 3, 9, 0.6, "BLOCK_NOTIFY")])
    assert merged == [Hit("Z", 0, 12, 0.6)] and actions == ["BLOCK_NOTIFY"]


def test_identical_spans_merge():
    merged, actions = _merge([("KR_RRN", 4, 18, 0.9, "MASK_FULL"), ("KR_FOREIGN_REGISTRATION_NUMBER", 4, 18, 0.9, "MASK_FULL")])
    assert len(merged) == 1 and (merged[0].start, merged[0].end) == (4, 18)


class _Stub:
    def __init__(self, entity_type, start, end):
        self.entity_type, self._span = entity_type, (start, end)

    def analyze(self, text):
        return [Hit(self.entity_type, *self._span, 0.9)] if len(text) >= self._span[1] else []


@pytest.fixture()
def mask_policies(tmp_path):
    import sqlite3

    db = tmp_path / "policy.db"
    c = sqlite3.connect(db)
    c.executescript("""CREATE TABLE detection_policies (policy_id TEXT PRIMARY KEY, target_type TEXT NOT NULL,
        target_value TEXT NOT NULL, action TEXT NOT NULL, priority INTEGER NOT NULL, version INTEGER NOT NULL,
        enabled INTEGER NOT NULL);
        INSERT INTO detection_policies VALUES ('POLICY-PII', 'CATEGORY', 'PII', 'MASK', 100, 1, 1);""")
    c.commit()
    c.close()
    policy_store.configure_database(str(db))
    yield
    policy_store.configure_database(None)


def test_detect_with_overlapping_hits_is_200_not_500(client: TestClient, monkeypatch, mask_policies):  # noqa: F811
    monkeypatch.setattr(engine, "RECOGNIZERS", (_Stub("KR_RRN", 4, 18), _Stub("KR_BANK_ACCOUNT", 10, 22)))
    text = "번호는 900101-1234567 99 끝"
    r = client.post("/detect", json={"request_id": "ov", "normalized_text": text})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pii_hits"] == "KR_BANK_ACCOUNT:1,KR_RRN:1"       # 건수는 합치기 전
    assert body["mask_spans"] == [{"start": 4, "end": 22, "entity_type": "KR_RRN"}]
    assert body["masked_text"] == text[:4] + "[KR_RRN]" + text[22:]
    assert [(f["start"], f["end"], f["policy_action"]) for f in body["findings"]] == [(4, 22, "mask_full")]


def test_detect_without_overlap_is_unchanged(client: TestClient, monkeypatch, mask_policies):  # noqa: F811
    monkeypatch.setattr(engine, "RECOGNIZERS", (_Stub("KR_RRN", 4, 18), _Stub("KR_BANK_ACCOUNT", 18, 22)))
    text = "번호는 900101-12345679999 끝"
    body = client.post("/detect", json={"request_id": "no", "normalized_text": text}).json()
    assert body["mask_spans"] == [{"start": 4, "end": 18, "entity_type": "KR_RRN"},
                                  {"start": 18, "end": 22, "entity_type": "KR_BANK_ACCOUNT"}]
    assert body["masked_text"] == text[:4] + "[KR_RRN][KR_BANK_ACCOUNT]" + text[22:]
