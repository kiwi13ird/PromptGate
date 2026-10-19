"""그래프 만들기(charts.py) - 눈금·0·빈 자료·감소 칩·긴 한글 이름 줄임(전체 이름은 <title>)·화면 안 글자 위치.

SVG는 XML로 읽혀야 하고(여는 태그·닫는 태그·따옴표), 모든 글자는 viewBox 안에 있어야 한다(넓은 판·좁은 판 모두).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import pytest

from reporting import charts as ch

NS = "{http://www.w3.org/2000/svg}"


def parse(svg: str) -> ET.Element:
    return ET.fromstring(svg)


def texts(root: ET.Element) -> list[ET.Element]:
    return list(root.iter(NS + "text"))


def own_text(el: ET.Element) -> str:
    return el.text or ""


def assert_inside(root: ET.Element, width: float) -> None:
    """모든 <text>가 viewBox 폭 안(앵커별로 글자 폭 어림)."""
    for t in texts(root):
        s = own_text(t)
        w = ch.text_w(s, 10.5 if "sm" in (t.get("class") or "") else 12)
        x = float(t.get("x"))
        anchor = t.get("text-anchor", "start")
        lo, hi = {"start": (x, x + w), "end": (x - w, x), "middle": (x - w / 2, x + w / 2)}[anchor]
        assert lo >= -1 and hi <= width + 1, (s, lo, hi, width)


# ---------------------------------------------------------------- 눈금

@pytest.mark.parametrize("vmax,top,step", [(0, 1, 1), (-3, 1, 1), (1, 1, 1), (3, 3, 1), (7, 8, 2), (12, 15, 5),
                                           (129, 150, 50), (1000, 1000, 500), (25000, 30000, 10000)])
def test_nice_scale(vmax, top, step):
    assert ch.nice_scale(vmax) == (top, step)


@pytest.mark.parametrize("vmax", [0.5, 1, 2, 9, 37, 99, 101, 640, 5001, 123456])
def test_nice_scale_covers_data_with_few_clean_ticks(vmax):
    top, step = ch.nice_scale(vmax)
    assert top >= vmax and step >= 1 and top % step == 0
    assert top / step <= 5
    mag = 10 ** (len(str(int(step))) - 1)
    assert step / mag in (1, 2, 5)


# ---------------------------------------------------------------- 글자 줄임

def test_fit_truncates_long_korean_and_keeps_short():
    long = "매우매우긴한국어문서이름_최종_수정본_검토완료_v2"
    shown, cut = ch.fit(long, 80)
    head, tail = shown.split("…")
    assert cut and head and tail and ch.text_w(shown) <= 80
    assert long.startswith(head) and long.endswith(tail)                     # 가운데만 줄여 앞·뒤가 남는다
    assert ch.fit("가나다라마바사아자차카타파하" * 3 + ".docx", 120)[0].endswith(".docx")
    assert ch.fit("짧은 이름", 80) == ("짧은 이름", False)
    assert ch.fit("가나다", 1) == ("…", True)       # 자리가 거의 없어도 깨지지 않는다


def rows_basic():
    return [{"label": "01_전략_보고서", "values": {"BLOCK": 5, "MASK": 3, "ALLOW": 2}},
            {"label": "서비스", "values": {"BLOCK": 0, "MASK": 0, "ALLOW": 0}}]


SERIES = [{"key": "BLOCK", "name": "차단", "cls": "block"}, {"key": "MASK", "name": "마스킹", "cls": "mask"},
          {"key": "ALLOW", "name": "허용", "cls": "allow"}]


@pytest.mark.parametrize("width", [ch.WIDE, ch.NARROW])
def test_long_label_truncated_with_full_label_in_title(width):
    full = "아주아주긴이름의보호문서_2026년_전략_보고서_최종본_수정2.docx"
    svg = ch.hbar_chart("t-" + str(width), "제목", "설명", [{"label": full, "values": {"BLOCK": 4}}], SERIES, width=width)
    root = parse(svg)
    hit = [t for t in texts(root) if t.find(NS + "title") is not None and t.find(NS + "title").text == full]
    assert len(hit) == 1
    shown = own_text(hit[0])
    assert "…" in shown and shown != full and shown.startswith(full[:3]) and shown.endswith(full[-3:])
    assert_inside(root, width)


@pytest.mark.parametrize("width", [ch.WIDE, ch.NARROW])
def test_hbar_zero_row_and_all_zero_do_not_break(width):
    svg = ch.hbar_chart("z", "제목", "설명", rows_basic(), SERIES, width=width)
    assert "nan" not in svg.lower() and "inf" not in svg.lower()
    root = parse(svg)
    zero = [t for t in texts(root) if own_text(t) == "0"]
    assert len(zero) == 1                                   # 값 0인 줄은 '0'만
    svg0 = ch.hbar_chart("z0", "제목", "설명", [{"label": "A", "values": {}}, {"label": "B", "values": {"BLOCK": 0}}],
                         SERIES, width=width)
    assert "nan" not in svg0.lower() and not list(parse(svg0).iter(NS + "path"))


def test_hbar_scale_is_shared_between_rows():
    rows = [{"label": "큰 것", "values": {"BLOCK": 10}}, {"label": "작은 것", "values": {"BLOCK": 5}}]
    root = parse(ch.hbar_chart("s", "제목", "설명", rows, SERIES, width=ch.WIDE))
    x0 = float(next(root.iter(NS + "line")).get("x1"))
    ends = {own_text(t): float(t.get("x")) for t in texts(root) if "tv" in (t.get("class") or "")}
    assert ends["10건"] > ends["5건"]
    assert (ends["10건"] - 6 - x0) == pytest.approx(2 * (ends["5건"] - 6 - x0), rel=0.02)


def test_hbar_stack_segments_have_values_and_shares_in_title():
    root = parse(ch.hbar_chart("s", "제목", "설명", rows_basic()[:1], SERIES, width=ch.WIDE))
    titles = [t.text for t in root.iter(NS + "title") if t.text and "·" in t.text]
    assert any("차단 5건 (50.0%)" in t for t in titles) and any("허용 2건 (20.0%)" in t for t in titles)


def test_hbar_share_mode_percent_sum_100():
    rows = [{"label": "이번", "values": {"BLOCK": 1, "MASK": 1, "ALLOW": 1}}]
    root = parse(ch.hbar_chart("sh", "제목", "설명", rows, SERIES, width=ch.WIDE, mode="share"))
    pcts = [float(m) for t in root.iter(NS + "title") if t.text for m in re.findall(r"\(([\d.]+)%\)", t.text)]
    assert len(pcts) == 3 and sum(pcts) == pytest.approx(100.0, abs=0.2)


def test_hbar_group_mode_and_badge_second_line():
    series = [{"key": "cur", "name": "이번", "cls": "secret"}, {"key": "prev", "name": "이전", "cls": "prev"}]
    rows = [{"label": "문서", "badge": "새로 차단", "values": {"cur": 3, "prev": 0}}]
    root = parse(ch.hbar_chart("g", "제목", "설명", rows, series, width=ch.NARROW, mode="group"))
    assert any(own_text(t) == "새로 차단" for t in texts(root))
    assert len([p for p in root.iter(NS + "path")]) == 1      # 이전 0은 막대 없이 '0'만
    assert_inside(root, ch.NARROW)


def test_bar_ends_are_rounded_only_on_the_data_end():
    d = ch._bar_path(10, 5, 100, 18, 4)
    assert d.startswith("M10 5H106a4 4 0 0 1 4 4") and d.endswith("H10z")     # 오른쪽 끝만 호, 왼쪽(기준선) 각짐
    assert ch._bar_path(10, 5, 1.5, 18, 4).count("a") == 2                    # 아주 짧아도 깨지지 않음


# ---------------------------------------------------------------- 선 그래프

DAYS = [f"2026-10-{d:02d}" for d in range(1, 8)]


def line_series(prev=True):
    s = [{"key": "total", "name": "검사", "cls": "total", "shape": "circle", "values": [0, 5, 9, 0, 3, 3, 12]},
         {"key": "block", "name": "차단", "cls": "block", "shape": "square", "values": [0, 1, 2, 0, 0, 1, 4]}]
    if prev:
        s[0]["prev"] = [1, 1, 0, 0, 2, 2, 2]
        s[1]["prev"] = [0, 0, 0, 0, 1, 0, 0]
    return s


@pytest.mark.parametrize("width", [ch.WIDE, ch.NARROW])
def test_line_chart_scale_zero_baseline_and_dashed_prev(width):
    svg = ch.line_chart("l", "제목", "설명", DAYS, line_series(), width=width, prev_days=[d.replace("-10-", "-09-") for d in DAYS])
    root = parse(svg)
    assert_inside(root, width)
    paths = list(root.iter(NS + "path"))
    assert [p.get("class") for p in paths] == ["ln s-total pv", "ln s-block pv", "ln s-total", "ln s-block"]
    # 0은 가장 아래 가로선(축)과 같은 높이, 최댓값 12는 위 끝(15)의 12/15 높이
    axis_y = float(next(l for l in root.iter(NS + "line") if l.get("class") == "g-axis").get("y1"))
    top_y = min(float(l.get("y1")) for l in root.iter(NS + "line"))
    d = paths[2].get("d")
    ys = [float(y) for y in re.findall(r"[ML][\d.]+ ([\d.]+)", d)]
    assert ys[0] == axis_y and ys[3] == axis_y
    assert (axis_y - ys[6]) / (axis_y - top_y) == pytest.approx(12 / 15, abs=0.01)
    labels = [own_text(t) for t in texts(root)]
    assert "10/1" in labels and "15" in labels and "12" in labels      # 한국 날짜 '월/일', 눈금, 가장 큰 날 값


def test_line_chart_without_prev_has_no_dashed_and_hit_titles_carry_values():
    root = parse(ch.line_chart("l", "제목", "설명", DAYS, line_series(prev=False), width=ch.WIDE))
    assert not [p for p in root.iter(NS + "path") if "pv" in p.get("class")]
    tips = [t.text for t in root.iter(NS + "title") if t.text and t.text.startswith("10/7")]
    assert tips == ["10/7 · 검사 12건 · 차단 4건"]


def test_line_chart_single_day_and_long_period():
    one = ch.line_chart("l1", "제목", "설명", ["2026-10-01"], [{"key": "t", "name": "검사", "cls": "total", "values": [4]}],
                        width=ch.NARROW)
    parse(one)
    n = 366
    days = [f"2026-{1 + i // 31:02d}-{1 + i % 28:02d}" for i in range(n)]
    ser = [{"key": "t", "name": "검사", "cls": "total", "values": [i % 7 for i in range(n)]}]
    svg = ch.line_chart("l2", "제목", "설명", days, ser, width=ch.WIDE)
    root = parse(svg)
    assert not list(root.iter(NS + "circle"))                              # 점이 겹칠 때는 선만
    assert not [r for r in root.iter(NS + "rect") if r.get("class") == "hit"]   # 띠는 120일까지만
    assert len([t for t in texts(root) if "/" in own_text(t)]) <= 14        # 날짜 눈금은 성기게
    assert_inside(root, ch.WIDE)


def test_line_chart_all_zero_series():
    svg = ch.line_chart("z", "제목", "설명", DAYS, [{"key": "t", "name": "검사", "cls": "total", "values": [0] * 7}], width=ch.WIDE)
    assert "nan" not in svg.lower()
    parse(svg)


# ---------------------------------------------------------------- 증감 칩

def test_delta_chip_up_down_same_and_missing():
    assert ">▲ 11 (+1,100%)<" in ch.delta_chip(12, 1)
    assert ">▲ 3 (+30.0%)<" in ch.delta_chip(13, 10)
    down = ch.delta_chip(7, 10)
    assert ">▼ 3 (-30.0%)<" in down and 'class="chip down"' in down and "줄어듦" in down
    assert "▲ 3<" in ch.delta_chip(3, 0) and "%" not in ch.delta_chip(3, 0)          # 이전 0이면 비율 없음
    assert "― 같음" in ch.delta_chip(5, 5) and "이전과 같음" in ch.delta_chip(5, 5)
    assert "비교 불가" in ch.delta_chip(5, None, comparable=False)
    assert ch.delta_chip(5, None, comparable=True) == ""
    assert ">▼ 120ms (-8.0%)<" in ch.delta_chip(1380, 1500, fmt=lambda v: f"{v:.0f}ms")


def test_delta_chip_keeps_no_judgement_word():
    for chip in (ch.delta_chip(9, 1), ch.delta_chip(1, 9)):
        assert "good" not in chip and "bad" not in chip and "악화" not in chip and "개선" not in chip


# ---------------------------------------------------------------- 덮개

def test_figure_has_both_widths_unique_ids_title_desc_and_escapes():
    def make(uid, w):
        return ch.hbar_chart(uid, "제목 <b>", "설명 & 설명", [{"label": "<i>x</i>", "values": {"BLOCK": 2}}], SERIES, width=w)

    fig = ch.figure("k", "제목 <b>", "부제", ch.legend_html([("block", "차단", "box")]), make,
                    ch.data_table("표", ["a", "b"], [["<i>", 1]]))
    assert fig.count("<svg") == 2 and 'class="v-wide"' in fig and 'class="v-narrow"' in fig
    assert "<b>" not in fig and "<i>x" not in fig
    ids = re.findall(r' id="([^"]+)"', fig)
    assert len(ids) == len(set(ids))
    for svg in re.findall(r"<svg.*?</svg>", fig, flags=re.S):
        root = parse(svg)
        assert root.get("role") == "img" and root.find(NS + "title") is not None and root.find(NS + "desc") is not None
        assert {root.find(NS + "title").get("id"), root.find(NS + "desc").get("id")} == set(root.get("aria-labelledby").split())
    assert 'class="sr-only"' in fig


def test_empty_figure_is_short_text_not_chart():
    fig = ch.empty_figure("e", "제목", "부제")
    assert "기록 없음" in fig and "<svg" not in fig


def test_data_table_visible_variant_is_details():
    t = ch.data_table("표", ["날짜", "검사"], [["10/1", 3]], visible=True)
    assert t.startswith("<details") and "표로 보기" in t and 'class="sr-only"' not in t


def test_hidden_data_table_is_wrapped_so_it_cannot_widen_the_page():
    t = ch.data_table("표", ["이름", "값"], [["아주 긴 이름" * 10, 3]])
    assert t.startswith('<div class="sr-only"><table>') and t.endswith("</table></div>")
    ET.fromstring(t)


def test_segment_labels_inside_bars_show_the_values():
    rows = [{"label": "행", "values": {"BLOCK": 50, "MASK": 30, "ALLOW": 20}}]
    root = parse(ch.hbar_chart("in", "제목", "설명", rows, SERIES, width=ch.WIDE))
    assert [own_text(t) for t in texts(root) if "in" in (t.get("class") or "").split()] == ["50", "30", "20"]
    assert [own_text(t) for t in texts(root) if t.get("class") == "tv"] == ["100건"]
    share = parse(ch.hbar_chart("in2", "제목", "설명", rows, SERIES, width=ch.WIDE, mode="share"))
    assert [own_text(t) for t in texts(share) if "in" in (t.get("class") or "").split()] == ["50.0%", "30.0%", "20.0%"]


def test_segment_label_skipped_when_it_does_not_fit():
    rows = [{"label": "행", "values": {"BLOCK": 1000, "MASK": 1}}]
    root = parse(ch.hbar_chart("in3", "제목", "설명", rows, SERIES, width=ch.NARROW))
    inside = [own_text(t) for t in texts(root) if "in" in (t.get("class") or "").split()]
    assert inside == ["1,000"]                       # 1건 조각은 글자가 안 들어가므로 쓰지 않는다(값은 title·표에)
