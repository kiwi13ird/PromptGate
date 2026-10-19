"""보고서 그래프 - 정적 SVG와 증감 칩 (2026-10-12 사용자 지적: 보고서에 그래프를 넣을 것).

- 자바스크립트·외부 글꼴·외부 그림 없음. 파일을 그대로 인쇄하거나 PDF로 저장해도 같게 나온다
- 그리는 숫자는 호출한 쪽이 넘긴 값(집계·사실 목록)뿐이다. 문장(LLM 글)에서 숫자를 읽어 오지 않는다
- 폭 둘(WIDE·NARROW)로 두 번 그리고 CSS가 화면 폭에 따라 하나만 보인다 - 좁은 화면에서 글자가 줄어들지 않게
- 접근성: 모든 SVG에 <title>·<desc>, 표 보기(보이지 않는 표 또는 접는 표), 색만으로 구분하지 않음(이름표·모양·값)
- 색은 template.html의 CSS 변수가 정한다. 여기서는 클래스 이름(f-*, s-*, on-*)만 붙인다
- 규격: 막대 두께 20px 이하·바깥 끝만 둥글게(4px), 조각 사이 2px 간격, 선 2px, 점 지름 8px 이상(주변 2px 고리), 눈금선 가는 실선
"""

from __future__ import annotations

import html
import math
import unicodedata

WIDE, NARROW = 600, 340          # viewBox 폭 (CSS 경계 640px)
GAP = 2.0                        # 쌓은 조각 사이 간격
BAR = 18.0                       # 막대 두께(쌓기·100%)
BAR_GROUP = 10.0                 # 나란히 막대 두께
FS = 12.0                        # 기본 글자 크기(viewBox 단위)
FS_SM = 10.5
MAX_TICKS = 4


# ---------------------------------------------------------------- 낱낱 도구

def esc(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _f(v: float) -> str:
    """좌표 표기 - 소수 한 자리, 끝 0 제거."""
    s = f"{v:.1f}"
    return s[:-2] if s.endswith(".0") else s


def n_fmt(v) -> str:
    return f"{int(round(v)):,}"


def md(iso: str) -> str:
    """'2026-10-05' → '10/5' (한국 날짜 문자열 그대로)."""
    y, m, d = iso.split("-")
    return f"{int(m)}/{int(d)}"


def text_w(s: str, size: float = FS) -> float:
    """글자 폭 어림(viewBox 단위) - 한글·전각 1.0, 숫자 0.58, 대문자 0.66, 좁은 기호 0.32, 그 밖 0.56."""
    w = 0.0
    for ch in str(s):
        if unicodedata.east_asian_width(ch) in ("W", "F"):
            w += 1.0
        elif ch.isdigit():
            w += 0.58
        elif ch.isupper():
            w += 0.66
        elif ch in " .,:;'|!il":
            w += 0.32
        elif ord(ch) > 127:
            w += 0.9
        else:
            w += 0.56
    return w * size


def fit(label: str, max_w: float, size: float = FS) -> tuple[str, bool]:
    """폭에 맞게 줄임 - (보일 글, 줄였는지). 가운데를 '…'로 줄여 앞(번호)과 뒤(확장자·끝 번호)를 둘 다 남긴다.
    전체 이름은 호출한 쪽이 <title>에 넣는다."""
    label = str(label)
    if text_w(label, size) <= max_w:
        return label, False
    budget = max_w - text_w("…", size)
    if budget <= 0:
        return "…", True
    head, used = "", 0.0
    for c in label:
        w = text_w(c, size)
        if used + w > budget * 0.6:
            break
        head, used = head + c, used + w
    tail, used_t = "", 0.0
    for c in reversed(label[len(head):]):
        w = text_w(c, size)
        if used + used_t + w > budget:
            break
        tail, used_t = c + tail, used_t + w
    return head + "…" + tail, True


def nice_scale(vmax: float, ticks: int = MAX_TICKS) -> tuple[float, float]:
    """(위 끝, 눈금 간격) - 간격은 1·2·5×10^k, 개수라서 1 미만으로 내려가지 않는다. 0 이하면 (1, 1)."""
    if not vmax or vmax <= 0:
        return 1.0, 1.0
    raw = vmax / ticks
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 5, 10) if raw <= m * mag + 1e-12)
    step = max(1.0, step)
    return math.ceil(vmax / step - 1e-12) * step, step


def pct(part: float, whole: float) -> float:
    return (part / whole * 100.0) if whole else 0.0


def _bar_path(x: float, y: float, w: float, h: float, r: float = 4.0) -> str:
    """바깥(오른쪽) 끝만 둥근 막대. 왼쪽(기준선)은 각지게."""
    r = max(0.0, min(r, w, h / 2))
    if r <= 0.05:
        return f"M{_f(x)} {_f(y)}h{_f(w)}v{_f(h)}h{_f(-w)}z"
    return (f"M{_f(x)} {_f(y)}H{_f(x + w - r)}a{_f(r)} {_f(r)} 0 0 1 {_f(r)} {_f(r)}V{_f(y + h - r)}"
            f"a{_f(r)} {_f(r)} 0 0 1 {_f(-r)} {_f(r)}H{_f(x)}z")


def _svg(uid: str, w: float, h: float, title: str, desc: str, body: str) -> str:
    return (f'<svg class="ch" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_f(w)} {_f(h)}" width="{_f(w)}" '
            f'height="{_f(h)}" role="img" aria-labelledby="{uid}-t {uid}-d">'
            f'<title id="{uid}-t">{esc(title)}</title><desc id="{uid}-d">{esc(desc)}</desc>{body}</svg>')


# ---------------------------------------------------------------- 가로 막대

def hbar_chart(uid: str, title: str, desc: str, rows: list[dict], series: list[dict], *, width: int,
               mode: str = "stack", unit: str = "건") -> str:
    """가로 막대 그래프.

    rows: [{label, values{키: 값}, badge(둘째 줄 이름표), tip(<title> 덧붙임)}]
    series: [{key, name, cls}] - 그리는 순서. cls는 f-<cls>(조각 색)·on-<cls>(조각 안 글자 색)
    mode: stack 쌓기(줄마다 합) · group 나란히(조각마다 값) · share 100%(줄마다 비율)
    줄 이름이 길면 줄이고(…) 전체 이름은 <title>에 둔다. 조각 안 글자는 들어갈 때만.
    """
    n = len(series)
    sm = mode == "group"
    bar_h = BAR_GROUP if sm else BAR
    block_h = n * bar_h + (n - 1) * 3 if sm else bar_h
    has_badge = any(r.get("badge") for r in rows)
    row_h = max(block_h + 14, 38 if has_badge else 0, 30)
    pad_t, pad_b, pad_l = 6.0, 6.0, 4.0
    cap = 150.0 if width >= 500 else 100.0
    label_w = min(max([text_w(r["label"]) for r in rows] + [text_w(r["badge"], FS_SM) for r in rows if r.get("badge")]
                      + [44.0]), cap)
    x0 = pad_l + label_w + 10

    def total(r):
        return sum(max(0, r["values"].get(s["key"], 0)) for s in series)

    if mode == "group":
        vmax = max([max(0, r["values"].get(s["key"], 0)) for r in rows for s in series] + [0])
        end_txt = max([text_w(n_fmt(r["values"].get(s["key"], 0))) for r in rows for s in series] + [0.0])
    else:
        vmax = max([total(r) for r in rows] + [0])
        end_txt = max([text_w(f"{n_fmt(total(r))}{unit}") for r in rows] + [0.0])
    L = max(40.0, width - x0 - end_txt - 12)
    k = (L / vmax) if vmax else 0.0
    h = pad_t + row_h * len(rows) + pad_b
    g = [f'<line class="g-axis" x1="{_f(x0)}" x2="{_f(x0)}" y1="{_f(pad_t)}" y2="{_f(h - pad_b)}"/>']
    for i, r in enumerate(rows):
        yr = pad_t + i * row_h
        cy = yr + row_h / 2
        shown, cut = fit(r["label"], label_w)
        tip = r.get("tip")
        t_title = f"<title>{esc(r['label'])}{' · ' + esc(tip) if tip else ''}</title>" if (cut or tip) else ""
        ly = cy + (-2 if r.get("badge") else 4)
        g.append(f'<text class="t" x="{_f(pad_l + label_w)}" y="{_f(ly)}" text-anchor="end">{esc(shown)}{t_title}</text>')
        if r.get("badge"):
            g.append(f'<text class="{r.get("badge_cls", "t2")} sm" x="{_f(pad_l + label_w)}" y="{_f(cy + 11)}" text-anchor="end">{esc(r["badge"])}</text>')
        y_blk = cy - block_h / 2
        vals = r["values"]
        if mode == "group":
            for j, s in enumerate(series):
                v = max(0, vals.get(s["key"], 0))
                y = y_blk + j * (bar_h + 3)
                tt = f"{r['label']} · {s['name']} {n_fmt(v)}{unit}"
                if v:
                    w = max(v * k, 2.0)
                    g.append(f'<path class="f-{s["cls"]}" d="{_bar_path(x0, y, w, bar_h)}"><title>{esc(tt)}</title></path>')
                    ex = x0 + w + 5
                else:
                    ex = x0 + 5
                g.append(f'<text class="{"tv" if j == 0 else "tm"}" x="{_f(ex)}" y="{_f(y + bar_h - 1.5)}">{n_fmt(v)}'
                         f'<title>{esc(tt)}</title></text>')
            continue
        tot = total(r)
        if tot <= 0:
            g.append(f'<text class="tm" x="{_f(x0 + 5)}" y="{_f(cy + 4)}">0</text>')
            continue
        scale = (L / tot) if mode == "share" else k
        live = [(s, vals.get(s["key"], 0)) for s in series if vals.get(s["key"], 0) > 0]
        x = x0
        for idx, (s, v) in enumerate(live):
            w = v * scale
            last = idx == len(live) - 1
            draw = w if last else max(w - GAP, 1.5)
            tt = f"{r['label']} · {s['name']} {n_fmt(v)}{unit}" + (f" ({pct(v, tot):.1f}%)" if len(live) > 1 or mode == "share" else "")
            g.append(f'<path class="f-{s["cls"]}" d="{_bar_path(x, y_blk, max(draw, 1.5), bar_h, 4.0 if last else 0.0)}">'
                     f'<title>{esc(tt)}</title></path>')
            lab = f"{pct(v, tot):.1f}%" if mode == "share" else n_fmt(v)
            if text_w(lab) + 10 <= draw:
                g.append(f'<text class="on-{s["cls"]} in" x="{_f(x + draw / 2)}" y="{_f(y_blk + bar_h / 2 + 4)}" '
                         f'text-anchor="middle">{lab}</text>')
            x += w
        g.append(f'<text class="tv" x="{_f(x + 6)}" y="{_f(y_blk + bar_h / 2 + 4)}">{n_fmt(tot)}{unit}</text>')
    return _svg(uid, width, h, title, desc, "".join(g))


# ---------------------------------------------------------------- 깔때기 (설계 v3 A2)

def funnel_chart(uid: str, title: str, desc: str, stages: list[dict], *, width: int, unit: str = "건") -> str:
    """단계별 가로 막대(깔때기). 막대는 모두 같은 기준선(왼쪽)에서 시작하고 길이는 한 눈금(가장 큰 단계 = 검사)을 쓴다.

    stages: [{label, parts: [{name, cls, value}], sub(막대 아래 작은 글, 선택)}] - 단계 안 조각은 쌓기.
    끝에는 단계 합 'N건'. 조각 안 숫자는 들어갈 때만, 값·단계 안 비율은 <title>과 표에. 좁은 판은 이름 칸을 줄인다.
    """
    pad_t, pad_b, pad_l = 6.0, 6.0, 4.0
    has_sub = any(s.get("sub") for s in stages)
    row_h = (BAR + 26.0) if has_sub else (BAR + 12.0)
    cap = 150.0 if width >= 500 else 96.0
    label_w = min(max([text_w(s["label"]) for s in stages] + [40.0]), cap)
    x0 = pad_l + label_w + 10
    totals = [sum(max(0, p["value"]) for p in s["parts"]) for s in stages]
    vmax = max(totals + [0])
    end_w = max([text_w(f"{n_fmt(t)}{unit}") for t in totals] + [0.0])
    L = max(40.0, width - x0 - end_w - 12)
    k = (L / vmax) if vmax else 0.0
    h = pad_t + row_h * len(stages) + pad_b
    g = [f'<line class="g-axis" x1="{_f(x0)}" x2="{_f(x0)}" y1="{_f(pad_t)}" y2="{_f(h - pad_b)}"/>']
    for i, (s, tot) in enumerate(zip(stages, totals)):
        y_bar = pad_t + i * row_h + 5
        cy = y_bar + BAR / 2
        shown, cut = fit(s["label"], label_w)
        t_title = f"<title>{esc(s['label'])}</title>" if cut else ""
        g.append(f'<text class="t" x="{_f(pad_l + label_w)}" y="{_f(cy + 4)}" text-anchor="end">{esc(shown)}{t_title}</text>')
        live = [p for p in s["parts"] if p["value"] > 0]
        x = x0
        for idx, p in enumerate(live):
            w = p["value"] * k
            last = idx == len(live) - 1
            draw = w if last else max(w - GAP, 1.5)
            tt = f"{s['label']} · {p['name']} {n_fmt(p['value'])}{unit}" + (f" ({pct(p['value'], tot):.1f}%)" if len(live) > 1 else "")
            g.append(f'<path class="f-{p["cls"]}" d="{_bar_path(x, y_bar, max(draw, 1.5), BAR, 4.0 if last else 0.0)}">'
                     f'<title>{esc(tt)}</title></path>')
            lab = n_fmt(p["value"])
            if text_w(lab) + 10 <= draw:
                g.append(f'<text class="on-{p["cls"]} in" x="{_f(x + draw / 2)}" y="{_f(y_bar + BAR / 2 + 4)}" '
                         f'text-anchor="middle">{lab}</text>')
            x += w
        g.append(f'<text class="tv" x="{_f((x if tot > 0 else x0) + 6)}" y="{_f(y_bar + BAR / 2 + 4)}">{n_fmt(tot)}{unit}</text>')
        if s.get("sub"):
            sub, cut2 = fit(s["sub"], width - x0 - 2, FS_SM)
            tip = f"<title>{esc(s['sub'])}</title>" if cut2 else ""
            g.append(f'<text class="tm sm" x="{_f(x0)}" y="{_f(y_bar + BAR + 13)}">{esc(sub)}{tip}</text>')
    return _svg(uid, width, h, title, desc, "".join(g))


# ---------------------------------------------------------------- 선 그래프

def _marker(shape: str, cx: float, cy: float, cls: str) -> str:
    if shape == "square":
        return f'<rect class="mk f-{cls}" x="{_f(cx - 4)}" y="{_f(cy - 4)}" width="8" height="8"/>'
    if shape == "diamond":
        pts = f"{_f(cx)},{_f(cy - 5.5)} {_f(cx + 5.5)},{_f(cy)} {_f(cx)},{_f(cy + 5.5)} {_f(cx - 5.5)},{_f(cy)}"
        return f'<polygon class="mk f-{cls}" points="{pts}"/>'
    return f'<circle class="mk f-{cls}" cx="{_f(cx)}" cy="{_f(cy)}" r="4"/>'


def line_chart(uid: str, title: str, desc: str, days: list[str], series: list[dict], *, width: int,
               prev_days: list[str] | None = None, unit: str = "건", changes: list[dict] | None = None) -> str:
    """일별 선 그래프. days: 한국 날짜(ISO). series: [{key, name, cls, shape, values, prev(선택)}].

    이전 기간 값(prev)은 같은 색 점선. 모든 선이 한 눈금을 씀(눈금 둘 아님). 제일 큰 날 값은 첫 선 위에 적는다.
    changes: 설정·정책·기준 변경 표시선 [{i: 날짜 위치, n: 번호, tip: <title> 글}] - 그 날 가운데 가는 세로 점선과 위쪽 번호(설계 v3 A4).
    """
    nd = len(days)
    wide = width >= 500
    vmax = max([v for s in series for v in (s["values"] + (s.get("prev") or []))] + [0])
    top, step = nice_scale(vmax)
    ml = text_w(n_fmt(top)) + 12
    mr, mt, mb = (12.0, 18.0, 26.0) if wide else (8.0, 18.0, 26.0)
    ph = (170.0 if wide else 150.0)
    h = mt + ph + mb
    pw = width - ml - mr
    band = pw / max(nd, 1)
    xs = [ml + (i + 0.5) * band for i in range(nd)]

    def y(v):
        return mt + ph - (v / top) * ph

    g = []
    t = 0.0
    while t <= top + 1e-9:
        g.append(f'<line class="{"g-axis" if t == 0 else "g-grid"}" x1="{_f(ml)}" x2="{_f(width - mr)}" y1="{_f(y(t))}" y2="{_f(y(t))}"/>')
        g.append(f'<text class="tm" x="{_f(ml - 6)}" y="{_f(y(t) + 4)}" text-anchor="end">{n_fmt(t)}</text>')
        t += step
    # 날짜 눈금 - 겹치지 않게 간격을 벌린다. 첫 날은 늘 적는다
    max_labels = max(2, int(pw // 46))
    every = max(1, math.ceil(nd / max_labels))
    marks = list(range(0, nd, every))
    if nd > 1 and (nd - 1) not in marks and (nd - 1) - marks[-1] >= max(1, every * 0.6):
        marks.append(nd - 1)
    for i in marks:
        g.append(f'<text class="tm" x="{_f(xs[i])}" y="{_f(h - 8)}" text-anchor="middle">{md(days[i])}</text>')
    for mk in changes or []:      # 변경 표시선 - 선·점 뒤에 깔리게 먼저 그린다
        if not 0 <= mk["i"] < nd:
            continue
        x = xs[mk["i"]]
        tip = f"<title>{esc(mk.get('tip') or '')}</title>" if mk.get("tip") else ""
        g.append(f'<line class="g-chg" x1="{_f(x)}" x2="{_f(x)}" y1="{_f(mt)}" y2="{_f(mt + ph)}">{tip}</line>')
        g.append(f'<text class="chg-n sm" x="{_f(x)}" y="{_f(mt - 5)}" text-anchor="middle">{esc(mk["n"])}{tip}</text>')
    dashed = any(s.get("prev") for s in series)
    if dashed:
        for s in series:
            pv = s.get("prev")
            if pv and len(pv) == nd:
                d = "".join(("M" if i == 0 else "L") + f"{_f(xs[i])} {_f(y(v))}" for i, v in enumerate(pv))
                g.append(f'<path class="ln s-{s["cls"]} pv" d="{d}"/>')
    for s in series:
        d = "".join(("M" if i == 0 else "L") + f"{_f(xs[i])} {_f(y(v))}" for i, v in enumerate(s["values"]))
        g.append(f'<path class="ln s-{s["cls"]}" d="{d}"/>')
    if pw / max(nd, 1) >= 14:      # 점이 겹치지 않을 때만 점을 찍는다
        for s in series:
            for i, v in enumerate(s["values"]):
                g.append(_marker(s.get("shape", "circle"), xs[i], y(v), s["cls"]))
    first = series[0]["values"] if series else []
    if first and max(first) > 0:
        i = first.index(max(first))
        anchor = "start" if xs[i] - 12 < ml else ("end" if xs[i] + 12 > width - mr else "middle")
        g.append(f'<text class="tv" x="{_f(xs[i])}" y="{_f(y(first[i]) - 9)}" text-anchor="{anchor}">{n_fmt(first[i])}</text>')
    if nd <= 120:                  # 날짜마다 마우스를 올리면 값이 보이는 세로 띠
        for i in range(nd):
            parts = [f"{md(days[i])}"] + [f"{s['name']} {n_fmt(s['values'][i])}{unit}" for s in series]
            tip = " · ".join(parts)
            if dashed and prev_days and i < len(prev_days):
                pv = [f"{s['name']} {n_fmt(s['prev'][i])}{unit}" for s in series if s.get("prev") and i < len(s["prev"])]
                if pv:
                    tip += f" / 이전 기간 {md(prev_days[i])}: " + " · ".join(pv)
            g.append(f'<rect class="hit" x="{_f(xs[i] - band / 2)}" y="{_f(mt)}" width="{_f(band)}" height="{_f(ph)}">'
                     f'<title>{esc(tip)}</title></rect>')
    return _svg(uid, width, h, title, desc, "".join(g))


# ---------------------------------------------------------------- 증감 칩

def delta_chip(value, prev, *, comparable: bool = True, fmt=None, small: bool = False) -> str:
    """카드 숫자 옆 증감 칩 - ▲ 늘어남 · ▼ 줄어듦 · ― 같음. 좋고 나쁨은 말하지 않는다(무채색).

    prev가 None이면 비교 기간이 없다는 뜻: comparable이 False면 '비교 불가', 아니면 칩 없음.
    fmt: 차이 값 글자 만들기(기본 천 단위 정수). 이전이 0이면 비율은 쓰지 않는다.
    small: 표본 적음(설계 v3 A4, frame.MIN_BASE) - 증감 %를 쓰지 않고 절대 증감만(분모 1에서 +5,400% 같은 오독 방지).
    """
    if prev is None or value is None:
        return '<span class="chip na">비교 불가</span>' if not comparable else ""
    fmt = fmt or n_fmt
    d = value - prev
    if abs(d) < 1e-9:
        return '<span class="chip same"><span aria-hidden="true">― 같음</span><span class="sr-only">이전과 같음</span></span>'
    up = d > 0
    arrow = "▲" if up else "▼"
    ratio = ""
    if prev and not small:
        p = d / abs(prev) * 100.0
        ratio = f" ({p:+,.0f}%)" if abs(p) >= 100 else f" ({p:+.1f}%)"
    word = "늘어남" if up else "줄어듦"
    label = f"이전 대비 {fmt(abs(d))} {word}{ratio}" + (" (비율 생략)" if small else "")
    return (f'<span class="chip {"up" if up else "down"}"><span aria-hidden="true">{arrow} {esc(fmt(abs(d)))}{esc(ratio)}</span>'
            f'<span class="sr-only">{esc(label)}</span></span>')


# ---------------------------------------------------------------- 그림 덮개·범례·표

def legend_html(items: list[tuple[str, str, str]]) -> str:
    """items: (cls, 글, 모양). 모양 box 네모 · dash 점선 · line 실선. 색 옆에 이름이 있어 색만으로 구분하지 않는다."""
    if not items:
        return ""
    out = []
    for cls, text, kind in items:
        key = {"box": f'<i class="f-{cls}"></i>', "dash": f'<i class="kd s-{cls}"></i>',
               "line": f'<i class="kl s-{cls}"></i>'}[kind]
        out.append(f"<span>{key}{esc(text)}</span>")
    return f'<div class="legend">{"".join(out)}</div>'


def data_table(caption: str, head: list[str], rows: list[list], *, visible: bool = False) -> str:
    """그래프의 숫자 표. visible=False는 화면에서 안 보이지만 읽기 도구는 읽는다(.sr-only 덮개). True는 접는 '표로 보기'."""
    th = "".join('<th scope="col"%s>%s</th>' % (' class="num"' if i else "", esc(h)) for i, h in enumerate(head))
    body = "".join("<tr>" + "".join(
        ('<th scope="row">%s</th>' if i == 0 else '<td class="num">%s</td>') % esc(c) for i, c in enumerate(r)) + "</tr>"
        for r in rows)
    tbl = '<table><caption>%s</caption><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (esc(caption), th, body)
    if not visible:
        # 표 자체에 sr-only를 걸면 줄바꿈 없는 표의 폭이 화면 밖으로 번져 가로 스크롤이 생긴다 → 덮개 div가 가둔다
        return '<div class="sr-only">%s</div>' % tbl
    return '<details class="table"><summary>표로 보기</summary><div class="tbl-wrap">%s</div></details>' % tbl


def _head(title: str, sub: str) -> str:
    subtxt = '<span class="sub">%s</span>' % esc(sub) if sub else ""
    return '<div class="chart-title"><h3>%s</h3>%s</div>' % (esc(title), subtxt)


def figure(key: str, title: str, sub: str, legend: str, make, table: str = "") -> str:
    """그래프 한 칸. make(uid, width) → SVG. 넓은 판·좁은 판을 둘 다 넣는다(CSS가 하나만 보임)."""
    return ('<figure class="chart fig" id="fig-%s">%s%s<div class="svgbox"><div class="v-wide">%s</div>'
            '<div class="v-narrow">%s</div></div>%s</figure>'
            % (esc(key), _head(title, sub), legend, make(f"{key}-w", WIDE), make(f"{key}-n", NARROW), table))


def empty_figure(key: str, title: str, sub: str = "") -> str:
    """자료가 없으면 빈 그래프 대신 한 줄."""
    return ('<figure class="chart fig empty" id="fig-%s">%s<p class="note">기록 없음</p></figure>'
            % (esc(key), _head(title, sub)))
