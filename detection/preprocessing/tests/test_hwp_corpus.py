"""실제 HWP 묶음 통계 시험(파일이 없으면 건너뜀). 문서 글자·파일 이름은 출력하지 않는다(실패 메시지에도 번호만).

  팀 HWP      HWP_TEAM_DIR   (기본: 사용자 PC의 '카카오톡 받은 파일', 하위 폴더 포함 19개)
  한컴 견본   HWP_HANCOM_DIR (기본: 한컴오피스 2024 설치 폴더, HWP 55개 + HWPX 계열 .hwtx 10개)

기준(명세 §1.3·§2.5 T1-1의 닫힌 목록 사전 측정): 팀 0/19, 견본 3/55가 hwp_unsupported_object(CTRL_DATA 2, 글맵시 1).
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from pathlib import Path

import fakeredis
import pytest

from preprocessing import hwpdoc
from preprocessing.normalizer import normalize_text
from preprocessing.router import process_input
from windowhash import detect, engine, index
from windowhash.hashing import WINDOW, compact, window_hashes

MAX = 20 * 1024 * 1024
TEAM = Path(os.environ.get("HWP_TEAM_DIR", r"C:/Users/user/Documents/카카오톡 받은 파일"))
HANCOM = Path(os.environ.get("HWP_HANCOM_DIR", r"C:/Program Files (x86)/HNC"))


def _files(root: Path, *suffixes: str) -> list[Path]:
    if not root.is_dir():
        pytest.skip(f"묶음 없음: {root}")
    files = sorted(p for p in root.rglob("*") if p.suffix.lower() in suffixes)
    if not files:
        pytest.skip(f"묶음 비어 있음: {root}")
    return files


def _subseq(a, b) -> bool:
    it = iter(b)
    return all(c in it for c in a)


def test_team_hwp_all_extract_and_register_consistently():
    files = _files(TEAM, ".hwp")
    stats = Counter()
    for i, f in enumerate(files):
        data = f.read_bytes()
        assert hwpdoc.sniff(data) == "hwp", i
        doc = hwpdoc.read(data, max_decompressed=MAX)               # 닫힌 목록: 팀 파일은 하나도 걸리지 않음
        lines = doc.body_lines()
        assert any(p.text.strip() for p in doc.paragraphs), i
        assert len({p.locator for p in doc.paragraphs}) == len(doc.paragraphs), i
        # 등록 경로(router) 글자는 본문 줄(+ 레코드 순서 보충 조각)로 시작하고, Gateway가 보낼 글자(본문 + 부가 글자)도
        # 같은 본문 줄로 시작한다(부가 글자는 등록하지 않음)
        parsed = process_input(str(f))
        assert parsed.success and parsed.format == "hwp", (i, parsed.error_type)
        reg = compact(parsed.normalized_text).codes
        body = compact(normalize_text("\n".join(lines))).codes
        assert reg[: len(body)] == body, i
        assert compact(normalize_text("\n".join(doc.lines()))).codes[: len(body)] == body, i
        # 부가 글자에만 있는 창(본문 어느 순서에도 없는 창)은 등록 색인에 없다
        body_w = set(window_hashes(body)) | set(window_hashes(compact(normalize_text(doc.paragraph_text())).codes))
        side_w = set(window_hashes(compact(normalize_text("\n".join(s.text for s in doc.side))).codes)) - body_w
        assert not side_w & set(window_hashes(reg)), i
        # 가운데서부터 이어진 본문 줄을 창 길이 이상 복사한 발췌가 등록 색인의 창과 모두 일치
        doc_hashes = {h for h, _, _ in engine.document_windows(parsed.normalized_text)}
        start = len(lines) // 2
        while start > 0 and sum(len(compact(l).codes) for l in lines[start:]) < WINDOW + 10:
            start -= 1
        end = start + 1
        while end < len(lines) and len(compact("\n".join(lines[start:end])).codes) < WINDOW + 10:
            end += 1
        passage = window_hashes(compact(normalize_text("\n".join(lines[start:end]))).codes)
        assert passage and all(h in doc_hashes for h in passage), i
        # 미리보기 글자는 본문(레코드 순서) 압축열의 부분열 - Gateway 미리보기 대조의 입력
        assert _subseq(compact(doc.preview_text()).codes, compact(doc.paragraph_text()).codes), i
        stats["files"] += 1
        stats["paragraphs"] += len(doc.paragraphs)
        stats["cell_paragraphs"] += sum(p.cell is not None for p in doc.paragraphs)
        stats["tables"] += doc.stats["tables"]
        for s in doc.side:
            stats[f"side_{s.kind}"] += 1
    print("team stats:", dict(stats))
    assert stats["files"] == len(files)


def test_hancom_samples_closed_list_matches_premeasurement():
    files = _files(HANCOM, ".hwp")
    outcome = Counter()
    for i, f in enumerate(files):
        data = f.read_bytes()
        assert hwpdoc.sniff(data) == "hwp", i
        try:
            doc = hwpdoc.read(data, max_decompressed=MAX)
        except hwpdoc.HwpUnsupported as exc:
            assert exc.kind == "hwp_unsupported_object", i
            outcome[exc.detail] += 1
            continue
        outcome["ok"] += 1
        assert _subseq(compact(doc.preview_text()).codes, compact(doc.paragraph_text()).codes), i
    print("hancom outcome:", dict(outcome))
    if len(files) == 55:                                     # 사전 측정과 같은 묶음일 때만 수치 비교
        assert outcome == Counter({"ok": 52, "tag87": 2, "tag90": 1})


def test_hancom_hwt_templates_closed_list():
    """한컴 기본 서식(.hwt, HWP 형식). 이 서식으로 만든 문서도 같은 개체를 가진다(2026-10-11 검토: .hwp만 세어 놓쳤음).
    10/11 측정(334개): 통과 271, CTRL_DATA(tag87) 39, XMLTemplate 스트림 21, 그림 아닌 BinData 3.
    글자 겹침(tcps)을 부가 글자로 뽑기 전에는 그것 하나 때문에만 23개가 더 막혔다(통과 248)."""
    files = _files(HANCOM, ".hwt")
    outcome = Counter()
    compose = Counter()
    for i, f in enumerate(files):
        data = f.read_bytes()
        assert hwpdoc.sniff(data) == "hwp", i
        try:
            doc = hwpdoc.read(data, max_decompressed=MAX)
        except hwpdoc.HwpUnsupported as exc:
            assert exc.kind == "hwp_unsupported_object", i
            outcome[exc.detail] += 1
            continue
        outcome["ok"] += 1
        n = sum(s.kind == "compose" for s in doc.side)
        compose["files"] += n > 0
        compose["texts"] += n
        assert _subseq(compact(doc.preview_text()).codes, compact(doc.paragraph_text()).codes), i
    print("hancom .hwt outcome:", dict(outcome), "compose:", dict(compose))
    assert "ctrl:tcps" not in outcome
    if len(files) == 334:                                    # 10/11 측정과 같은 묶음일 때만 수치 비교
        assert outcome == Counter({"ok": 271, "tag87": 39, "stream": 21, "bindata": 3})
        assert compose == Counter({"files": 23, "texts": 357})


def test_hancom_hwpx_family_templates_parse_without_unknown_text():
    files = _files(HANCOM, ".hwtx", ".hwpx")
    for i, f in enumerate(files):
        data = f.read_bytes()
        assert hwpdoc.sniff(data) == "hwpx", i
        doc = hwpdoc.read(data, max_decompressed=MAX)
        assert doc.kind == "hwpx" and doc.paragraphs, i
        assert _subseq(compact(doc.preview_text()).codes, compact(doc.paragraph_text()).codes), i


def test_project_synthetic_pii_files_extract_fake_values():
    root = Path(os.environ.get("HWP_SYNTH_DIR", r"C:/Users/user/Desktop/kisia/project/reports"))
    files = [f for f in _files(root, ".hwp", ".hwpx") if "마스킹후" not in f.name]
    rrn = re.compile(r"\d{6}-\d{7}")
    for i, f in enumerate(files):
        doc = hwpdoc.read(f.read_bytes(), max_decompressed=MAX)
        assert rrn.search("\n".join(doc.lines())), i          # 가짜 주민번호가 검사 글자에 들어감


# ---------------------------------------------------------------- 본문이 무관한 문서끼리 차단 없음(검토 지적 1)

def _distinct_body_docs(files: list[Path]) -> list[dict]:
    """본문이 다른 문서만(같은 본문 사본은 하나). reg = 등록 경로 글자, upload = Gateway가 보낼 글자(정규화)."""
    docs, seen = [], set()
    for f in files:
        try:
            doc = hwpdoc.read(f.read_bytes(), max_decompressed=MAX)
        except hwpdoc.HwpError:
            continue                                                # 닫힌 목록에 걸린 견본은 등록 대상 아님
        if not any(p.text.strip() for p in doc.paragraphs):
            continue
        body = normalize_text("\n".join(doc.body_lines()))
        key = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        parsed = process_input(str(f))
        assert parsed.success, (len(docs), parsed.error_type)
        record_order = normalize_text(doc.paragraph_text())          # 등록 경로의 레코드 순서 보충 조각도 본문 글자
        docs.append({"reg": parsed.normalized_text, "upload": normalize_text("\n".join(doc.lines())),
                     "body": set(window_hashes(compact(body).codes)) | set(window_hashes(compact(record_order).codes))})
    return docs


def _block_outcomes(docs: list[dict]) -> tuple[Counter, Counter]:
    """(하나만 등록하고 다른 문서를 올린 순서쌍, 하나만 빼고 모두 등록한 뒤 뺀 문서를 올린 경우)의 결과 수.
    본문 창이 하나도 안 겹치는데 차단 = FALSE_block, 겹치는데 통과 = missed."""
    pairs = Counter()
    for ai, a in enumerate(docs):
        r = fakeredis.FakeRedis(decode_responses=True)
        index.replace_doc_windows(r, "a", engine.document_windows(a["reg"]))
        for bi, b in enumerate(docs):
            if ai == bi:
                continue
            blocked = detect.decide(detect.query_text(r, b["upload"])).blocked
            overlap = bool(a["body"] & b["body"])
            pairs["true_block" if blocked and overlap else "FALSE_block" if blocked else "missed" if overlap else "pass"] += 1
    loo = Counter()
    for bi, b in enumerate(docs):
        r = fakeredis.FakeRedis(decode_responses=True)
        for ai, a in enumerate(docs):
            if ai != bi:
                index.replace_doc_windows(r, f"d{ai:03d}", engine.document_windows(a["reg"]))
        decision = detect.decide(detect.query_text(r, b["upload"]))
        if not decision.blocked:
            loo["pass"] += 1
            continue
        ai = int(decision.signal.x_evidence[1:4])
        loo["true_block" if docs[ai]["body"] & b["body"] else "FALSE_block"] += 1
    return pairs, loo


def test_team_hwp_unrelated_bodies_are_not_blocked():
    docs = _distinct_body_docs(_files(TEAM, ".hwp"))
    pairs, loo = _block_outcomes(docs)
    print("team distinct bodies:", len(docs), "pairs:", dict(pairs), "leave-one-out:", dict(loo))
    assert pairs["FALSE_block"] == 0 and loo["FALSE_block"] == 0
    assert pairs["missed"] == 0
    if len(docs) == 17:                                      # 검토 때 잰 묶음(본문이 다른 17개)
        assert pairs["true_block"] == 24                     # 본문이 겹치는 순서쌍은 그대로 차단


def test_hancom_hwpx_templates_unrelated_bodies_are_not_blocked():
    docs = _distinct_body_docs(_files(HANCOM, ".hwtx", ".hwpx"))
    pairs, loo = _block_outcomes(docs)
    print("hwpx distinct bodies:", len(docs), "pairs:", dict(pairs), "leave-one-out:", dict(loo))
    assert pairs["FALSE_block"] == 0 and loo["FALSE_block"] == 0
    assert pairs["missed"] == 0
