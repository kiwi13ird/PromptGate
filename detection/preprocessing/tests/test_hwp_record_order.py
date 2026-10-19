"""등록 색인의 레코드 순서 보충 시험(2026-10-11 검토 지적: lines() 배치 vs 한컴 글자 순서). 글자는 모두 가짜 값.

lines()는 칸 안의 중첩 표를 그 행 뒤로 옮긴다. 한컴은 글자를 레코드(요소) 순서로 다루므로(미리보기 PrvText도 이 순서),
중첩 표 경계를 걸치는 짧은 복사 발췌는 lines() 배치의 창과 하나도 안 맞을 수 있다(검토 실측: 팀 HWP #17·#18에서 PrvText
창이 79%·85%만 색인에 있고 연속 29창이 빠짐 - 그 자리를 걸치는 압축 58자 이하 발췌는 통과). 등록 경로는 레코드 순서
본문(paragraph_text)의 창 중 등록 배치에 없는 것만 덮는 조각을 덧붙인다(hwp_parser.record_order_supplement).
"""

from __future__ import annotations

import os
from pathlib import Path

import fakeredis
import pytest

import hwp_synth as S
from hwp_synth import hp_p, hp_t, hp_tbl, hp_tc
from preprocessing import hwp_parser, hwpdoc
from preprocessing.normalizer import normalize_text
from preprocessing.router import process_input
from windowhash import engine, index
from windowhash.hashing import compact, window_hashes

MAX = hwp_parser.MAX_DECOMPRESSED
HEAD = "보고서 머리 문단: 가짜 납품 단가 재협상 결과 보고"
A1 = "첫 칸 첫 문단: 가짜 협력사 세 곳과 맺은 납품 단가 재협상 결과를 아래 표로 정리한다"
N1 = "중첩 표 왼쪽 칸: 가짜 협력사 갑의 단가 인하율 사점오 퍼센트"
N2 = "중첩 표 오른쪽 칸: 가짜 협력사 을의 단가 인하율 이점일 퍼센트"
A2 = "첫 칸 끝 문단: 인하분은 다음 분기 원가 계획에 반영하고 품질 조건은 그대로 둔다"
B = "둘째 칸: 담당 부서 가짜 구매팀, 보고 일자 가짜 이천이십육년 시월"


def _hwp() -> bytes:
    """칸 (0,0) = A1, [중첩 표 N1 | N2], A2 / 칸 (0,1) = B. lines(): 'A1\\nA2 | B' 다음 줄 'N1 | N2'."""
    nested = S.para(2, S.ext_ctrl(11, "tbl "), S.table(3, [(0, 0, 1, 1, [S.p(4, N1)]), (0, 1, 1, 1, [S.p(4, N2)])], 1, 2))
    tbl = S.table(1, [(0, 0, 1, 1, [S.p(2, A1), nested, S.p(2, A2)]), (0, 1, 1, 1, [S.p(2, B)])], 1, 2)
    return S.build_hwp([S.p(0, HEAD) + S.para(0, S.ext_ctrl(11, "tbl "), tbl)])


def _hwpx() -> bytes:
    nested = hp_tbl([[hp_tc(0, 0, hp_p(hp_t(N1))), hp_tc(0, 1, hp_p(hp_t(N2)))]])
    tbl = hp_tbl([[hp_tc(0, 0, hp_p(hp_t(A1)) + hp_p(nested) + hp_p(hp_t(A2))), hp_tc(0, 1, hp_p(hp_t(B)))]])
    return S.build_hwpx([hp_p(hp_t(HEAD)) + hp_p(tbl)])


def _windows(text: str) -> list[int]:
    return window_hashes(compact(normalize_text(text)).codes)


def _register(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    parsed = process_input(str(path))
    assert parsed.success, (parsed.error_type, parsed.error_message)
    return parsed.normalized_text


def _blocks(tmp_path, name: str, data: bytes, monkeypatch, *, supplement: bool) -> list[dict]:
    path = tmp_path / name
    path.write_bytes(data)
    parse = hwp_parser.parse_hwp if name.endswith(".hwp") else hwp_parser.parse_hwpx
    if supplement:
        return parse(path)
    with monkeypatch.context() as m:
        m.setattr(hwp_parser, "record_order_supplement", lambda doc, blocks: [])
        return parse(path)


@pytest.mark.parametrize("name,make", [("n.hwp", _hwp), ("n.hwpx", _hwpx)])
def test_record_order_windows_are_all_registered(tmp_path, monkeypatch, name, make):
    data = make()
    doc = hwpdoc.read(data, max_decompressed=MAX)
    assert doc.lines()[:3] == [HEAD, f"{A1}\n{A2} | {B}", f"{N1} | {N2}"]           # 배치는 그대로(Gateway와 같음)
    record = _windows(doc.paragraph_text())
    base = _blocks(tmp_path, name, data, monkeypatch, supplement=False)
    base_windows = set(_windows(hwp_parser._blocks_text(base)))
    assert sum(h not in base_windows for h in record) > 0                         # 보충 없으면 빠지는 창이 있음
    full = _blocks(tmp_path, name, data, monkeypatch, supplement=True)
    assert full[: len(base)] == base and len(full) > len(base)                    # 등록 배치 뒤에 조각만 덧붙임
    pieces = [b["text"] for b in full[len(base):]]
    assert all(b["type"] == "paragraph" for b in full[len(base):])
    assert sum(len(compact(p).codes) for p in pieces) < len(compact(normalize_text(doc.paragraph_text())).codes)
    registered = {h for h, _, _ in engine.document_windows(_register(tmp_path, name, data))}
    assert all(h in registered for h in record)


@pytest.mark.parametrize("excerpt", [A1[-28:] + "\n" + N1[:28], N2[-28:] + " " + A2[:28]])
def test_short_excerpt_across_nested_table_boundary_is_blocked(tmp_path, excerpt):
    """중첩 표 경계를 걸치는 짧은 발췌(한컴 레코드 순서로 복사, 압축 37~38자 - 양쪽 모두 창 길이 30 미만이라 모든 창이
    경계를 걸침). 수정 전: 창 0개 일치 → 통과."""
    data = _hwp()
    r = fakeredis.FakeRedis(decode_responses=True)
    index.replace_doc_windows(r, "plan", engine.document_windows(_register(tmp_path, "n.hwp", data)))
    hashes = _windows(excerpt)
    assert hashes
    signals = engine.query(r, "아래 내용 다듬어줘\n" + excerpt)
    assert signals and signals[0].x_evidence == "plan"


def test_hwp_and_hwpx_same_structure_give_same_supplement(tmp_path, monkeypatch):
    pieces = []
    for name, make in (("n.hwp", _hwp), ("n.hwpx", _hwpx)):
        base = _blocks(tmp_path, name, make(), monkeypatch, supplement=False)
        pieces.append(_blocks(tmp_path, name, make(), monkeypatch, supplement=True)[len(base):])
    assert pieces[0] == pieces[1] and pieces[0]


def test_no_supplement_when_record_order_matches_layout(tmp_path, monkeypatch):
    """칸 안 중첩 표가 칸 끝에 있으면(합성 표본: 중첩 표가 칸 마지막 문단) 두 순서의 압축열이 같아 덧붙이는 것이 없다."""
    from test_hwpdoc_hwp import _sample

    data = _sample()
    assert _blocks(tmp_path, "s.hwp", data, monkeypatch, supplement=True) == \
        _blocks(tmp_path, "s.hwp", data, monkeypatch, supplement=False)


# ---------------------------------------------------------------- 실제 묶음(파일 없으면 건너뜀, 통계만 출력)

TEAM = Path(os.environ.get("HWP_TEAM_DIR", r"C:/Users/user/Documents/카카오톡 받은 파일"))
HANCOM = Path(os.environ.get("HWP_HANCOM_DIR", r"C:/Program Files (x86)/HNC"))


def _corpus(root: Path, *suffixes: str) -> list[Path]:
    if not root.is_dir():
        pytest.skip(f"묶음 없음: {root}")
    files = sorted(p for p in root.rglob("*") if p.suffix.lower() in suffixes)
    if not files:
        pytest.skip(f"묶음 비어 있음: {root}")
    return files


def _coverage(files: list[Path]) -> dict:
    stats = {"files": 0, "record_windows": 0, "record_missing": 0, "preview_windows": 0, "preview_missing": 0,
             "files_with_supplement": 0, "supplement_chars": 0, "preview_missing_files": []}
    original = hwp_parser.record_order_supplement
    pieces: list[list[str]] = []

    def spy(doc, blocks):
        out = original(doc, blocks)
        pieces.append(out)
        return out

    for i, f in enumerate(files):
        data = f.read_bytes()
        try:
            doc = hwpdoc.read(data, max_decompressed=MAX)
        except hwpdoc.HwpError:
            continue                                            # 닫힌 목록에 걸린 파일은 등록 대상 아님
        with pytest.MonkeyPatch.context() as m:
            m.setattr(hwp_parser, "record_order_supplement", spy)
            pieces.clear()
            parsed = process_input(str(f))
        if not parsed.success:
            continue                                            # 본문 글자 없는 서식 등
        stats["files_with_supplement"] += bool(pieces and pieces[-1])
        stats["supplement_chars"] += sum(len(p) for p in pieces[-1]) if pieces else 0
        registered = {h for h, _, _ in engine.document_windows(parsed.normalized_text)}
        record = _windows(doc.paragraph_text())
        preview = _windows(doc.preview_text())
        stats["files"] += 1
        stats["record_windows"] += len(record)
        stats["record_missing"] += sum(h not in registered for h in record)
        stats["preview_windows"] += len(preview)
        missing = sum(h not in registered for h in preview)
        stats["preview_missing"] += missing
        if missing:
            stats["preview_missing_files"].append(i)
    return stats


def test_team_hwp_record_order_and_preview_windows_are_registered():
    files = _corpus(TEAM, ".hwp")
    stats = _coverage(files)
    print("team record-order coverage:", stats)
    assert stats["files"] == len(files)
    assert stats["record_missing"] == 0
    assert stats["preview_missing"] == 0                       # 수정 전: #17 87창·#18 53창 빠짐


def test_hancom_record_order_windows_are_registered():
    """한컴 견본·서식(.hwp·.hwt·.hwtx). 미리보기는 견본 2개가 짧은 영문 본문 문단을 빼고 이어 붙여(순서 문제 아님)
    그 이음 창이 없으므로 통계만 출력한다."""
    files = _corpus(HANCOM, ".hwp", ".hwt", ".hwtx")
    stats = _coverage(files)
    print("hancom record-order coverage:", stats)
    assert stats["files"] > 0 and stats["record_missing"] == 0
