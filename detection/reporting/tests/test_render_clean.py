"""보고서 HTML 화면 (2026-10-12 사용자 지적): 그래프를 넣고 출처 표시는 모두 뺀다.

1) 출처 표시 없음 - 어떤 모드(LLM 좋음·나쁨·일부 실패·집계만·블라인드)에서도 옛 표시 문구·클래스·사실 번호가 안 남는다.
   문장 출처·인용·버린 문장은 생성 기록 JSON에만 있다
2) 섹션·그래프 순서 고정(스냅숏), 인쇄 서식, 외부 요청·스크립트 없음
3) 그래프 숫자는 집계 값(카드·사실 목록)이고 LLM 글과 무관하다: LLM 좋음·나쁨·집계만이어도 그래프 HTML이 같다
4) 칩(▲▼), 빈 자료('기록 없음'), 감소(▼)
"""

from __future__ import annotations

import html as H
import json
import re
import sys
import types
import xml.etree.ElementTree as ET

import pytest

from reporting import llm
from reporting import __main__ as M

from fake_llm import FakeLLM
from render_markers import assert_no_provenance, visible_text
from synth import FakeConn, ev
from test_pipeline import run

# 설계 v3(2026-10-13): 번호 없는 '한 장 요약'(맨 앞)·'차단 뒤 재요청'(5절 뒤)·'관측 범위'(9절 뒤)가 생기고, 주요 사건에
# 같은 패턴 묶음 카드(사건 10·11), 11절에 '정의·기준'이 붙었다. 번호 붙은 절의 순서·그래프는 그대로.
SECTIONS = [
    ("한 장 요약", ["funnel"], ["검사에서 노출까지"]),
    ("1. 요약", ["comp"], ["조치 구성"]),
    ("2. 판정 현황", ["daily", "svc"], ["일별 추이", "서비스별 조치", "조치 × 사유", "경로별"]),
    ("3. 기밀정보", ["docs"], ["보호 문서별 차단", "보호 문서 상세"]),
    ("4. 개인정보·인증정보", ["pii", "fmt"], ["유형별 처리", "파일 형식별 처리", "유형 상세", "파일 형식 상세"]),
    ("5. 주요 사건", [], ["사건 1", "사건 3", "사건 2", "사건 8", "같은 패턴 사건 2건", "사건 10", "사건 11", "사건 12", "사건 13",
                       "사건 5", "사건 6", "사건 7"]),
    ("차단 뒤 재요청", [], ["01_전략_보고서", "검사 불가 파일(그 밖 형식)", "인증정보 차단(GitHub 토큰)", "02_채용_평가서"]),
    ("6. 사용자별 위험", ["risk"], ["사용자 위험 분포"]),
    ("7. 내용 경향", ["content"], ["내용 범주별 건수"]),
    ("8. 설정·정책 변경", [], ["관리 작업", "변경·기준 변경"]),
    ("9. 운영 상태", [], ["검사 없이 통과 사유", "판정만 있는 요청"]),
    ("관측 범위(못 본 것)", [], []),
    ("10. 권고·다음 조치", [], ["기밀 차단", "새로 차단된 문서", "인증정보 노출 시도", "검사 없이 통과", "기록 누락", "탐지 단계 오류"]),
    ("11. 참고", [], ["정의·기준"]),
]


def outline(doc: str) -> list[tuple[str, list[str], list[str]]]:
    out = []
    for p in re.split(r'(?=<section aria-labelledby=")', doc)[1:]:
        h2 = H.unescape(re.search(r"<h2[^>]*>([^<]+)</h2>", p).group(1))
        figs = re.findall(r'<figure class="chart fig[^"]*" id="fig-(\w+)"', p)
        h3 = [H.unescape(x) for x in re.findall(r"<h3>([^<]+)</h3>", p)]
        # 그래프 제목은 <figure> 안 h3. 표 제목 등과 섞이므로 h3 전체를 순서대로 둔다
        out.append((h2, figs, h3))
    return out


def figures(doc: str) -> dict[str, str]:
    return {m.group(1): m.group(0) for m in re.finditer(r'<figure class="chart fig[^"]*" id="fig-(\w+)".*?</figure>', doc, flags=re.S)}


@pytest.fixture
def good(tmp_path, monkeypatch):
    with FakeLLM("good") as fake:
        rc, doc, log, _ = run(tmp_path, monkeypatch, fake.url)
    assert rc == 0
    return doc, log


# ---------------------------------------------------------------- 1) 출처 표시 없음

def test_no_provenance_in_any_mode(tmp_path, monkeypatch):
    seen = {}
    with FakeLLM("good") as fake:
        rc, doc, log, _ = run(tmp_path, monkeypatch, fake.url, "--blind", name="r_good")
        seen["good"] = doc
        seen["blindA"] = (tmp_path / "r_good.blind-A.html").read_text(encoding="utf-8")
        seen["blindB"] = (tmp_path / "r_good.blind-B.html").read_text(encoding="utf-8")
    with FakeLLM("bad") as fake:
        seen["bad"] = run(tmp_path, monkeypatch, fake.url, name="r_bad")[1]
    monkeypatch.setattr(llm, "CALL_TIMEOUT", 1.0)
    with FakeLLM("good", fail={"commentary": "badjson", "narrate": "timeout"}) as fake:
        seen["partial"] = run(tmp_path, monkeypatch, fake.url, name="r_part")[1]
    with FakeLLM("good") as fake:
        seen["nollm"] = run(tmp_path, monkeypatch, fake.url, "--no-llm", name="r_sql")[1]
        seen["nocontent"] = run(tmp_path, monkeypatch, fake.url, "--no-content-trend", name="r_nc")[1]
    seen["gpu_down"] = run(tmp_path, monkeypatch, "http://127.0.0.1:9/v1/chat/completions", name="r_down")[1]
    assert len(seen) == 8
    for mode, doc in seen.items():
        assert_no_provenance(doc)


def test_blind_files_equal_the_report_shape(tmp_path, monkeypatch):
    """블라인드 비교판 둘은 어느 쪽이 LLM인지 HTML만으로 알 수 없다 - 머리·바닥·문장 앞뒤 표시가 같다."""
    with FakeLLM("good") as fake:
        rc, doc, log, _ = run(tmp_path, monkeypatch, fake.url, "--blind")
    a, b = (re.sub(r"생성 \d{4}-\d{2}-\d{2} \d{2}:\d{2}", "", (tmp_path / f"report_x.blind-{x}.html").read_text(encoding="utf-8"))
            for x in ("A", "B"))
    head = lambda s: s.split("</header>")[0]            # noqa: E731
    assert head(a) == head(b)
    assert a.split("<footer>")[1] == b.split("<footer>")[1]
    assert set(log["blind"].values()) == {"llm", "sql"}      # 어느 쪽인지는 JSON에만


def test_provenance_lives_in_json_only(good):
    doc, log = good
    prov = log["provenance"]
    sents = prov["sentences"]
    assert sents and {s["src"] for s in sents} == {"llm", "sql"}
    assert sum(1 for s in sents if s["src"] == "llm") == log["kept"]
    assert all(s["cites"] for s in sents if s["src"] == "llm")                 # LLM 문장은 인용을 가짐
    assert all({"sec", "kind", "src", "text", "cites", "tpl"} <= set(s) for s in sents)
    assert prov["rank"]["src"] == "llm" and prov["rank"]["order"]
    assert {x["user"] for x in prov["levels"]} and all(x["level_src"] in ("llm", "rule") for x in prov["levels"])
    assert {x["issue"] for x in prov["actions"]} >= {"R1", "R3"} and all(x["action_src"] for x in prov["actions"])
    # 문장 글은 보고서에 그대로 나온다(출처 표시만 없음)
    for s in sents:
        assert H.escape(s["text"], quote=True) in doc, s["text"]
    # 인용 번호는 HTML 글에 안 나온다
    text = visible_text(doc)
    for s in sents:
        for c in s["cites"]:
            assert not re.search(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(c), text), c


def test_dropped_lines_stay_in_json_not_in_html(tmp_path, monkeypatch):
    with FakeLLM("bad") as fake:
        rc, doc, log, _ = run(tmp_path, monkeypatch, fake.url)
    assert log["dropped"] and all({"section", "line", "why"} <= set(d) for d in log["dropped"])
    text = visible_text(doc)
    for d in log["dropped"]:
        if len(d["line"]) > 6:
            assert d["line"] not in text
    assert "sql" in {s["src"] for s in log["provenance"]["sentences"]}      # 버려진 자리는 집계 문장


def test_no_fact_id_shown_for_documents_in_incident_steps(good):
    doc, _ = good
    assert "기밀 차단 01_전략_보고서" in visible_text(doc)      # 단계 글의 문서 번호(D1)는 문서 이름으로


# ---------------------------------------------------------------- 2) 순서·인쇄·외부 요청

def test_section_and_figure_order_snapshot(good):
    doc, _ = good
    assert outline(doc) == SECTIONS


def test_section_order_without_content_trend_drops_only_its_figure(tmp_path, monkeypatch):
    with FakeLLM("good") as fake:
        rc, doc, log, _ = run(tmp_path, monkeypatch, fake.url, "--no-llm")
    got = outline(doc)
    assert [x[0] for x in got] == [s[0] for s in SECTIONS]
    assert [x[1] for x in got] == [s[1] if s[0] != "7. 내용 경향" else [] for s in SECTIONS]


def test_print_css_and_self_contained(good):
    doc, _ = good
    for needle in ("@media print", "@page", "size: A4", "break-inside: avoid", "print-color-adjust: exact",
                   "thead { display: table-header-group; }", ".v-narrow { display: none !important; }",
                   "@media (max-width: 640px)"):
        assert needle in doc, needle
    assert re.search(r"@media print \{.*?:root, :root:not\(\[data-theme=\"light\"\]\), :root\[data-theme=\"dark\"\] \{", doc, flags=re.S)  # 어두운 설정이어도 종이는 흰 바탕
    assert not re.search(r"<script|<link|@import|url\(|<img|<iframe|<object", doc, flags=re.I)
    assert not re.search(r'(?:href|src)="(?!#|/)[^"]+"', doc)           # 바깥 주소 없음(조치 링크는 /로 시작하는 대시보드 경로)
    assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", doc)
    assert "fonts.googleapis" not in doc


def test_svgs_well_formed_accessible_and_have_tables(good):
    doc, _ = good
    figs = figures(doc)
    assert set(figs) == {"funnel", "comp", "daily", "svc", "docs", "pii", "fmt", "risk", "content"}   # funnel: 설계 v3 A2
    ids = re.findall(r' id="([^"]+)"', doc)
    assert len(ids) == len(set(ids))                                       # id 중복 없음(두 폭·여러 그래프)
    for key, fig in figs.items():
        svgs = re.findall(r"<svg.*?</svg>", fig, flags=re.S)
        assert len(svgs) == 2, key                                         # 넓은 판 + 좁은 판
        widths = []
        for svg in svgs:
            root = ET.fromstring(svg)
            ns = "{http://www.w3.org/2000/svg}"
            assert root.get("role") == "img" and root.get("viewBox") and root.find(ns + "title").text and root.find(ns + "desc").text
            widths.append(float(root.get("viewBox").split()[2]))
        assert widths == [600.0, 340.0], key
        assert 'class="sr-only"' in fig or "<details" in fig, key          # 표 보기
        assert "<caption>" in fig


def test_charts_never_exceed_viewbox_in_a_full_report(good):
    from test_charts import assert_inside
    doc, _ = good
    for svg in re.findall(r'<svg class="ch".*?</svg>', doc, flags=re.S):
        root = ET.fromstring(svg)
        assert_inside(root, float(root.get("viewBox").split()[2]))


# ---------------------------------------------------------------- 3) 그래프 숫자는 집계 값

def test_chart_numbers_match_cards_and_ignore_llm_text(tmp_path, monkeypatch):
    out = {}
    with FakeLLM("good") as fake:
        out["good"] = run(tmp_path, monkeypatch, fake.url, name="a")[1:3]
    with FakeLLM("bad") as fake:
        out["bad"] = run(tmp_path, monkeypatch, fake.url, name="b")[1:3]
    with FakeLLM("good") as fake:
        out["sql"] = run(tmp_path, monkeypatch, fake.url, "--no-llm", name="c")[1:3]
    for mode in ("bad", "sql"):
        for key in ("comp", "daily", "svc", "docs", "pii", "fmt"):
            assert figures(out["good"][0])[key] == figures(out[mode][0])[key], (mode, key)
    doc, log = out["good"]
    c = log["cards"]
    comp = figures(doc)["comp"]
    row = re.search(r"<th scope=\"row\">이번 기간</th>((?:<td class=\"num\">[\d,]+</td>)+)", comp).group(1)
    assert [int(x.replace(",", "")) for x in re.findall(r">([\d,]+)<", row)] == [c["block"], c["mask"], c["allow"], c["total"]]
    daily = figures(doc)["daily"]
    totals = [int(x) for x in re.findall(r"<tr><th scope=\"row\">\d+/\d+</th><td class=\"num\">(\d+)</td>", daily)]
    assert sum(totals) == c["total"] and len(totals) == 12                  # 10/1~10/12 모든 날(기록 없는 날 0)
    svc = figures(doc)["svc"]
    assert sum(int(x) for x in re.findall(r"<th scope=\"row\">[^<]+</th><td class=\"num\">\d+</td><td class=\"num\">\d+</td><td class=\"num\">\d+</td><td class=\"num\">(\d+)</td>", svc)) == c["total"]
    # 사용자 위험 그래프는 최종 등급(LLM이 바꿀 수 있는 값을 검사 통과한 것) 개수 = 사용자 표의 등급 개수
    risk = figures(doc)["risk"]
    lv = dict(re.findall(r"<th scope=\"row\">(높음|중간|낮음)</th><td class=\"num\">(\d+)</td>", risk))
    assert sum(int(v) for v in lv.values()) == log["users"]
    assert int(lv["높음"]) == log["users_high"]


# ---------------------------------------------------------------- 4) 칩·빈 자료·감소

def test_summary_cards_have_change_chips(good):
    """설계 v3 A4로 바뀜: 합성 자료는 이번 29건·이전 1건(표본 적음 기준 30 미만) → 증감 %는 빼고 절대 증감만, 카드에 '표본 적음'.
    (옛 기대값 '▲ 11 (+1,100%)'·'▲ 28 (+2,800%)'은 분모 1의 오독이라 없어져야 한다)"""
    doc, _ = good
    cards = re.findall(r'<div class="kpi" id="k-F_[A-Z_]+">.*?</div>', doc, flags=re.S)
    assert len(cards) == 6 and all('class="chip ' in c for c in cards)
    assert all("표본 적음" in c for c in cards)
    assert '<span aria-hidden="true">▲ 11</span>' in doc                   # 기밀 차단 1→12, % 없음
    assert '<span aria-hidden="true">▲ 28</span>' in doc                   # 검사 1→29, % 없음
    assert "+1,100%" not in doc and "+2,800%" not in doc
    secret = next(c for c in cards if "k-F_SECRET" in c)
    assert "이전 1" in secret and '<span class="sr-only">이전 대비 11 늘어남 (비율 생략)</span>' in secret      # 읽기 도구용 글
    assert "1,000건당" not in secret                                        # 분모가 작으면 1,000건당 비율도 안 씀


def conn_from(events, decs=()):
    return FakeConn(events, list(decs), [])


def run_conn(tmp_path, monkeypatch, conn, *args, name="r"):
    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(connect=lambda dsn, autocommit=False: conn))
    monkeypatch.setenv("DETECTION_PG_DSN", "postgresql://fake")
    monkeypatch.setenv("REPORT_CONTENT_TREND", "off")
    out = tmp_path / f"{name}.html"
    rc = M.main(["--from", "2026-10-01", "--to", "2026-10-13", "--out", str(out), "--no-local-api", "--no-llm", *args])
    return rc, out.read_text(encoding="utf-8")


def test_decrease_shows_down_chip_and_prev_dashed_line(tmp_path, monkeypatch):
    evs = [ev(f"2026-09-{19 + i % 8} 10:{i:02d}:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt",
              docs=["01_전략_보고서"], eid=f"p{i}") for i in range(12)]
    evs += [ev(f"2026-09-{19 + i % 8} 11:{i:02d}:00", "chrome-aaaa-0001", "ChatGPT", "ALLOW", eid=f"q{i}") for i in range(8)]
    evs += [ev("2026-09-19 00:00:00", "chrome-aaaa-0001", "ChatGPT", "ALLOW", eid="p0"),     # 이전 기간 첫 순간 → 비교 가능
            ev("2026-10-03 10:00:00", "chrome-aaaa-0001", "ChatGPT", "ALLOW", eid="c1"),
            ev("2026-10-04 10:00:00", "chrome-aaaa-0001", "Claude", "ALLOW", eid="c2")]
    rc, doc = run_conn(tmp_path, monkeypatch, conn_from(evs))
    assert rc == 0
    # 설계 v3 A4로 바뀜: 이전 21건·이번 2건은 표본 적음 → 옛 기대값 '▼ 19 (-90.5%)'·'▼ 12 (-100%)'에서 %가 빠진다
    assert '<span aria-hidden="true">▼ 19</span>' in doc and 'class="chip down"' in doc   # 검사 21→2
    assert '<span aria-hidden="true">▼ 12</span>' in doc                  # 기밀 차단 12→0
    assert "-90.5%" not in doc and "(-100%)" not in doc
    assert 'class="ln s-total pv"' in doc                                   # 이전 기간 점선
    assert_no_provenance(doc)
    assert "새로 차단" not in doc                                           # 이번 기간에 막힌 문서가 없다 → 문서 그래프는 '기록 없음'
    assert 'id="fig-docs"' in doc and re.search(r'id="fig-docs">.*?기록 없음', doc, flags=re.S)


def test_empty_database_shows_no_record_text_not_empty_charts(tmp_path, monkeypatch):
    rc, doc = run_conn(tmp_path, monkeypatch, conn_from([]))
    assert rc == 0
    for key in ("comp", "daily", "svc", "docs", "pii", "fmt"):
        fig = figures(doc)[key]
        assert "기록 없음" in fig and "<svg" not in fig, key
    assert 'class="ch"' not in doc
    assert "비교 불가" in doc                                               # 이전 기간 기록 없음 → 칩은 '비교 불가'
    assert_no_provenance(doc)


def test_not_comparable_period_has_no_dashed_line_and_na_chip(tmp_path, monkeypatch):
    evs = [ev("2026-10-03 10:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=["01_전략_보고서"], eid="x1"),
           ev("2026-10-04 10:00:00", "chrome-aaaa-0001", "ChatGPT", "MASK", rc="pii", ents={"KR_PHONE_NUMBER": 1}, eid="x2")]
    rc, doc = run_conn(tmp_path, monkeypatch, conn_from(evs))
    assert 'class="ln s-total pv"' not in doc and 'class="chip na"' in doc
    assert figures(doc)["comp"].count("이전 기간") == 0 or "이전 기간" not in re.findall(r"<tr><th scope=\"row\">([^<]+)</th>", figures(doc)["comp"])


def test_long_document_name_is_truncated_in_doc_chart_with_full_name_in_title(tmp_path, monkeypatch):
    long_doc = "아주아주긴이름의보호문서_2026년_전략_보고서_최종본_수정2_검토완료"
    evs = [ev("2026-10-03 10:00:00", "chrome-aaaa-0001", "ChatGPT", "BLOCK", rc="doc_excerpt", docs=[long_doc], eid="x1")]
    rc, doc = run_conn(tmp_path, monkeypatch, conn_from(evs))
    fig = figures(doc)["docs"]
    assert f"<title>{long_doc}" in fig and fig.count("…") >= 2              # 넓은 판·좁은 판 모두 줄임(가운데 …)
    labels = re.findall(r'<text class="t"[^>]*>([^<]*)<title>' + re.escape(long_doc) + "</title></text>", fig)
    assert len(labels) == 2 and all("…" in x and x.startswith("아주아주") and x.endswith(long_doc[-2:]) for x in labels)
    assert_no_provenance(doc)


# ---------------------------------------------------------------- 그림 속 숫자 = 표 숫자

def table_cells(fig: str) -> dict[tuple[str, str], int]:
    """그림의 숫자 표 → {(줄 이름, 칸 이름): 값}."""
    t = re.search(r"<table.*?</table>", fig, flags=re.S).group(0)
    head = [H.unescape(x) for x in re.findall(r'<th scope="col"[^>]*>([^<]*)</th>', t)]
    cells = {}
    for row in re.findall(r"<tr><th scope=\"row\">.*?</tr>", t, flags=re.S):
        name = H.unescape(re.search(r'<th scope="row">([^<]*)</th>', row).group(1))
        vals = re.findall(r'<td class="num">([^<]*)</td>', row)
        for col, v in zip(head[1:], vals):
            if re.fullmatch(r"[\d,]+", v):
                cells[(name, col)] = int(v.replace(",", ""))
    return cells


def svg_titles(fig: str) -> list[str]:
    wide = re.search(r'<div class="v-wide">(<svg.*?</svg>)</div>', fig, flags=re.S).group(1)
    return [H.unescape(x) for x in re.findall(r"<title>([^<]+)</title>", wide)]          # id가 붙은 그림 제목은 제외됨


@pytest.mark.parametrize("key,suffix", [("comp", "건"), ("svc", "건"), ("pii", "건"), ("fmt", "건"), ("docs", "건"),
                                        ("content", "건"), ("risk", "명")])
def test_numbers_drawn_in_bars_equal_numbers_in_table(good, key, suffix):
    doc, _ = good
    fig = figures(doc)[key]
    cells = table_cells(fig)
    got = set()
    for t in svg_titles(fig):
        m = re.fullmatch(r"(.+?) · (.+?) ([\d,]+)%s(?: \([\d.]+%%\))?" % suffix, t)
        if not m:
            continue                                                       # 줄 이름 전체·덧붙임 글
        row, col, n = m.group(1), m.group(2), int(m.group(3).replace(",", ""))
        if key == "risk":
            row, col = col, "사용자"
        assert cells[(row, col)] == n, (t, cells.get((row, col)))
        got.add((row, col))                                                # 막대·값 글자가 같은 title을 가짐
    drawn = {k for k, v in cells.items() if v and k[1] != "합계"}
    assert drawn <= got                                                    # 0이 아닌 칸은 모두 막대 조각으로 그려졌다


def test_daily_line_values_equal_table(good):
    doc, _ = good
    fig = figures(doc)["daily"]
    table = {}
    for row in re.findall(r"<tr><th scope=\"row\">(\d+/\d+)</th>((?:<td class=\"num\">\d+</td>)+)", fig):
        table[row[0]] = [int(x) for x in re.findall(r">(\d+)<", row[1])]          # 검사·차단·마스킹·허용·(이전)
    tips = {}
    for t in svg_titles(fig):
        m = re.match(r"(\d+/\d+) · 검사 (\d+)건 · 차단 (\d+)건 · 마스킹 (\d+)건", t)
        if m:
            tips[m.group(1)] = [int(m.group(i)) for i in (2, 3, 4)]
    assert tips and set(tips) == set(table)
    assert all(tips[d] == table[d][:3] for d in tips)


def test_every_figure_has_wide_and_narrow_inside_their_containers(good):
    doc, _ = good
    for key, fig in figures(doc).items():
        assert re.search(r'<div class="v-wide"><svg.*?</svg></div><div class="v-narrow"><svg.*?</svg></div>', fig, flags=re.S), key
