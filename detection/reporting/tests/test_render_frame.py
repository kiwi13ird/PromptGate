"""보고서 틀(설계 v3 A1~A5, A9 요약 쪽) 화면 시험 - 합성 DB로 끝까지 만든 HTML을 본다.

1) 집계만(LLM 없음)으로도 새 블록이 모두 나온다: 한 장 요약(1. 요약 앞)·깔때기·차단 뒤 재요청·같은 패턴 카드·관측 범위·정의·기준
2) 한 장 요약은 코드만 쓴다 - LLM판과 집계판이 글자까지 같고, 새 사실 번호는 LLM 요청에 한 번도 안 간다
3) 표본 적음이 아닐 때는 % 칩·1,000건당 비율이 나온다 · 빈 DB는 '확인 불가'·그래프 대신 '기록 없음'
4) 조치 링크는 기존 링크 함수(build_link)·REPORT_ACCESS_BLOCK_LINK 동작 그대로 · 인쇄 쪽 넘김 CSS · 새 블록 글에 금지어 없음
"""

from __future__ import annotations

import re

import pytest

from reporting import frame as fr
from reporting import wording

from fake_llm import FakeLLM
from render_markers import assert_no_provenance, visible_text
from synth import FakeConn, ev
from test_pipeline import run
from test_render_clean import conn_from, figures, run_conn

GPU_DOWN = "http://127.0.0.1:9/v1/chat/completions"


def block(doc: str, sid: str) -> str:
    m = re.search(r'<section aria-labelledby="[^"]+" id="%s".*?</section>' % sid, doc, flags=re.S)
    assert m, sid
    return m.group(0)


@pytest.fixture
def sql_doc(tmp_path, monkeypatch):
    rc, doc, log, _ = run(tmp_path, monkeypatch, GPU_DOWN, "--no-llm", name="r_sql")
    assert rc == 0 and log["mode"] == "sql"
    return doc


# ---------------------------------------------------------------- 1) 집계만으로 새 블록 전부

def test_fallback_render_has_every_new_block_in_order(sql_doc):
    doc = sql_doc
    pos = [doc.index(x) for x in ('id="sum"', 'class="part-label"', 'id="s1"', 'id="s5"', 'id="bypass"', 'id="s6"',
                                   'id="s9"', 'id="cov"', 'id="s10"', 'id="defs"')]
    assert pos == sorted(pos)                                        # 한 장 요약 → 본문 → 1. 요약 … 관측 범위 → 권고 → 정의
    vis = visible_text(doc.split("</header>", 1)[1])                  # 목차(머리) 뒤 본문 글 순서
    assert vis.index("한 장 요약") < vis.index("본문") < vis.index("1. 요약")
    s = block(doc, "sum")
    assert ">위험<" in s and "표본 적음" in s                          # 노출 69.0·차단 뒤 통과 3·검사 못 함 103.4 → 위험
    assert "10/1–10/12에 29건을 검사해 15건 차단, 5건 마스킹, 2건은 검사 없이 통과" in s
    assert "기밀 차단 1→12건(+11건)" in s and "개인정보 마스킹 0→5건(+5건)" in s
    assert 'id="fig-funnel"' in s and s.count("<svg") >= 2
    assert "검사 29건 중 탐지·검사 못 함 22건 → 차단·마스킹 20건, 노출 2건 · 나머지 7건은 탐지 없이 허용" in s
    for href in ('href="#cov"', 'href="#bypass"', 'href="#s10"'):
        assert href in s
    assert "업계 기준 아님" in s
    # 조치 권고 줄은 기존 이슈 이름·수준만(결정 필요 분류는 자료에 없어 만들지 않음)
    assert "결정 필요" not in vis and "높음 3(기밀 차단 · 인증정보 노출 시도 · 검사 없이 통과)" in s
    b = block(doc, "bypass")
    assert b.count('<article class="bp') == 4 and "차단 뒤 통과 3건(식별 사용자 3명)" in b
    c = block(doc, "cov")
    assert c.count('id="cov-') == 12 and c.count(f'<span class="na">{fr.NA}</span>') == 4   # 승인 대기 키워드·반영 시점(이번·이전)
    assert 'id="defs"' in block(doc, "s11")
    assert_no_provenance(doc)
    ids = re.findall(r' id="([^"]+)"', doc)
    assert len(ids) == len(set(ids))


def test_same_pattern_group_card_keeps_individual_cards_and_anchors(sql_doc):
    s5 = block(sql_doc, "s5")
    grp = re.search(r'<article class="inc grp g1" id="grp-I10">.*?</details>\s*</article>', s5, flags=re.S).group(0)
    assert "<h3>같은 패턴 사건 2건</h3>" in grp and "식별 0 · 미식별 2" in grp and "10/8 14:30–15:00" in grp
    assert 'href="#card-I10"' in grp and 'href="#card-I11"' in grp
    inner = grp.split('<details class="grp-more">', 1)[1]
    assert 'id="card-I10"' in inner and 'id="card-I11"' in inner                 # 사건별 카드(번호·링크)는 안쪽에
    assert s5.count('id="card-I10"') == 1
    assert 'href="#card-I10"' in s5.split('<div class="inc-all">')[1]            # 사건 전체 표(토글 없이 바로 보임) 링크도 그대로
    assert "<summary>사건 전체</summary>" not in s5


def test_daily_chart_has_change_lines_from_criteria_changes(sql_doc):
    fig = figures(sql_doc)["daily"]
    assert fig.count('class="g-chg"') == 6                       # 10/9·10/11·10/12 × 넓은 판·좁은 판
    lst = re.search(r'<ul class="chg-list".*?</ul>', fig, flags=re.S).group(0)
    assert "10/9" in lst and "16:20 마스킹한 글 기록 시작" in lst and "10/11" in lst and "10/12" in lst


def test_print_page_break_after_onepage_and_layout_css(sql_doc):
    css = re.search(r"@media print \{.*?\n\}\n</style>", sql_doc, flags=re.S).group(0)
    assert ".onepage { break-after: page; page-break-after: always;" in css
    assert "word-break: keep-all" in sql_doc
    assert re.search(r"@media \(max-width: 520px\) \{[^@]*table\.cov tr \{ display: grid;", sql_doc)


# ---------------------------------------------------------------- 2) LLM과 무관

FRAME_IDS = [fid for fid, _, _ in fr.FRAME_FACTS] + ["F_BYPASS"]


def test_onepage_is_code_only_and_new_facts_never_reach_llm(tmp_path, monkeypatch):
    with FakeLLM("good") as fake:
        rc, doc, log, _ = run(tmp_path, monkeypatch, fake.url, name="r_llm")
        assert rc == 0 and log["llm_used"]
        bodies = [r["body"] for r in fake.requests]
    for fid in FRAME_IDS:
        assert not any(re.search(r"\b%s\b" % fid, b) for b in bodies), fid       # 프롬프트·허용 목록에 없음
    with FakeLLM("bad") as fake:
        bad = run(tmp_path, monkeypatch, fake.url, name="r_bad")[1]
    sql = run(tmp_path, monkeypatch, GPU_DOWN, "--no-llm", name="r_sql2")[1]
    for sid in ("sum", "cov"):
        assert block(doc, sid) == block(bad, sid) == block(sql, sid), sid          # 숫자·문장 모두 코드
    # 차단 뒤 재요청의 사용자 링크만 6절과 같은 최종 등급을 따른다(LLM이 바꾼 등급) - 링크를 빼면 같다
    strip = lambda s: re.sub(r'<span class="act-wrap">.*?</span></span>', "", s)      # noqa: E731
    assert strip(block(doc, "bypass")) == strip(block(bad, "bypass")) == strip(block(sql, "bypass"))
    assert figures(doc)["funnel"] == figures(sql)["funnel"]
    assert_no_provenance(doc)


# ---------------------------------------------------------------- 3) 표본 적음 아님 · 빈 DB

def big_conn() -> FakeConn:
    """이전 9/19~9/30 40건(기밀 차단 4), 이번 10/1~10/12 60건(기밀 차단 9·검사 없이 통과 3)."""
    evs = [ev("2026-09-19 00:00:00", "chrome-aaaa-0001", "ChatGPT", "ALLOW", eid="p0")]
    for i in range(39):
        blk = i < 4
        evs.append(ev(f"2026-09-{20 + i % 10} 10:{i:02d}:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK" if blk else "ALLOW",
                      rc="doc_excerpt" if blk else None, docs=["01_전략_보고서"] if blk else (), eid=f"p{i + 1}"))
    for i in range(60):
        kind = "doc" if i < 9 else ("unchk" if i < 12 else "ok")
        evs.append(ev(f"2026-10-{1 + i % 12:02d} 11:{i:02d}:00", "chrome-bbbb-0002", "Claude",
                      "BLOCK" if kind == "doc" else "ALLOW", "file" if kind == "unchk" else "prompt",
                      rc={"doc": "doc_excerpt", "unchk": "file_uninspectable_image"}.get(kind),
                      docs=["01_전략_보고서"] if kind == "doc" else (), eid=f"c{i}"))
    return conn_from(evs)


def test_large_base_shows_percent_chips_and_per_1000(tmp_path, monkeypatch):
    rc, doc = run_conn(tmp_path, monkeypatch, big_conn())
    assert rc == 0
    cards = re.findall(r'<div class="kpi" id="k-F_[A-Z_]+">.*?</div>', doc, flags=re.S)
    assert len(cards) == 6 and not any('class="smallb"' in c for c in cards)   # 검사 30건 이상: 카드 라벨에 표본 적음 딱지 없음
    secret = next(c for c in cards if "k-F_SECRET" in c)
    assert '<span aria-hidden="true">▲ 5</span>' in secret and "%)" not in secret.split("1,000건당")[0]   # 4→9: 이전 건수 4건(<MIN_PREV_COUNT)이라 % 없이 절대 증감만
    assert "1,000건당 150.0 · 이전 100.0" in secret
    total = next(c for c in cards if "k-F_TOTAL" in c)
    assert "1,000건당" not in total                                              # 검사 카드는 분모라 비율 없음
    s = block(doc, "sum")
    assert "기밀 차단 4→9건(+5건) · 1,000건당 100.0→150.0" in s and "표본 적음" not in s
    assert ">위험<" in s                                                         # 노출 3/60 = 1,000건당 50
    assert "1,000건당 50.0" in s and "식별 안 됨 0건(0.0%)" in s


def test_empty_database_status_unavailable_and_no_funnel_chart(tmp_path, monkeypatch):
    rc, doc = run_conn(tmp_path, monkeypatch, conn_from([]))
    assert rc == 0
    s = block(doc, "sum")
    assert f">{fr.NA}<" in s and "이전 기간 기록 없음(비교 불가)" in s
    assert "기록 없음" in figures(doc)["funnel"] and "<svg" not in figures(doc)["funnel"]
    assert "해당 없음" in block(doc, "bypass")
    assert fr.NO_PREV in block(doc, "cov")
    assert_no_provenance(doc)


# ---------------------------------------------------------------- 4) 링크·금지어

def test_bypass_links_use_existing_link_builder(tmp_path, monkeypatch):
    monkeypatch.delenv("REPORT_ACCESS_BLOCK_LINK", raising=False)
    b = block(run(tmp_path, monkeypatch, GPU_DOWN, "--no-llm", name="off")[1], "bypass")
    assert "/events?documentId=01_%EC%A0%84%EB%9E%B5_%EB%B3%B4%EA%B3%A0%EC%84%9C&amp;period=30D" in b      # 문서 차단 이력
    assert "/events?q=chrome-aaaa-0001&amp;period=30D" in b and "접속 차단 화면 반영 전" in b             # 차단 링크 꺼짐 → 사용자 기록
    assert "/policies/access" not in b
    monkeypatch.setenv("REPORT_ACCESS_BLOCK_LINK", "on")
    b = block(run(tmp_path, monkeypatch, GPU_DOWN, "--no-llm", name="on")[1], "bypass")
    assert "/policies/access?block=chrome-aaaa-0001&amp;reason=LEAK_DOC_REPEAT" in b and "이 사용자 차단" in b
    assert "/policies/access?block=chrome-bbbb-0002&amp;reason=PII_REPEAT" in b                          # 인증정보 사용자
    assert "/events?q=chrome-cccc-0003&amp;period=30D" in b                                              # 중간·기밀/인증정보 없음 → 기록


def test_new_blocks_rendered_text_passes_wording_rules(sql_doc):
    parts = [block(sql_doc, "sum"), block(sql_doc, "bypass"), block(sql_doc, "cov"),
             re.search(r'<div class="defs".*?</dl></div>', sql_doc, flags=re.S).group(0),
             re.search(r'<ul class="chg-list".*?</ul>', sql_doc, flags=re.S).group(0)]
    for p in parts:
        p = re.sub(r'<span class="(?:path mono|lnote)">.*?</span>', " ", p)       # 링크 경로·링크 메모(기존 문구)는 제외
        p = re.sub(r"<details class=\"table\">.*?</details>", " ", p, flags=re.S)
        for line in re.split(r"\s·\s|\n", visible_text(p)):
            assert wording.find_banned(line) is None, (line, wording.find_banned(line))


# ---------------------------------------------------------------- 검토 반영

def test_retry_group_cards_are_capped_with_remainder_note(tmp_path, monkeypatch):
    monkeypatch.setattr(fr, "MAX_GROUPS", 2)
    rc, doc, log, _ = run(tmp_path, monkeypatch, GPU_DOWN, "--no-llm", name="r_cap")
    assert rc == 0
    b = block(doc, "bypass")
    assert b.count('<article class="bp') == 2                                   # 합성 자료 묶음 4개 중 2개만
    m = re.search(r"외 (\d+)묶음\(사건 (\d+)건\)은 줄여 보였습니다", b)
    assert m and m.group(1) == "2" and int(m.group(2)) >= 2
    assert "차단 뒤 통과 3건(식별 사용자 3명)" in b                                # 머리 줄은 줄여도 전체 값


def test_bypass_headline_in_onepage_matches_bypass_block(sql_doc):
    head = re.search(r"차단 뒤 통과 \d+건\(식별 사용자 \d+명\)[^<]*", block(sql_doc, "sum")).group(0)
    assert head in block(sql_doc, "bypass")                                     # 한 장 요약과 본문이 같은 함수·같은 값


def test_coverage_row_ids_unique_and_prev_wording(sql_doc):
    c = block(sql_doc, "cov")
    ids = re.findall(r' id="(cov-[^"]*)"', c)
    assert len(ids) == len(set(ids)) and "cov-" not in [i for i in ids if i == "cov-"]
    assert "이전 이전" not in c and "이전 이전" not in visible_text(sql_doc)
