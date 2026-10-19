"""HTML 렌더 - 섹션 0~11 (설계 v2 4.2). 표·카드·그래프는 코드, 문장은 검사 통과한 LLM 문장 또는 집계 문장.

2026-10-12 사용자 지적 반영:
- 그래프(정적 SVG, charts.py)와 카드 숫자 옆 증감 칩을 넣는다
- 출처 표시(LLM·집계 이름표, 인용 번호, 작성 방식, 순위 출처, 문장 출처 범례)는 HTML에 쓰지 않는다. 문장은 그냥 보고서 글이다.
  어느 문장이 LLM에서 왔는지·인용·버린 문장은 생성 기록 JSON에만 남는다(provenance.py).
블라인드 비교판은 같은 화면이다(출처 표시가 처음부터 없음).

설계 v3 틀(A1~A5, A9 요약 쪽, 계산은 frame.py - 코드만):
- 머리 뒤 '한 장 요약'(상태·첫 문장·이전 대비·깔때기·관측 범위 한 줄·차단 뒤 재요청 한 줄·조치 권고) → 인쇄하면 첫 쪽, 뒤에서 쪽 넘김
- 카드: 표본 적음이면 증감 % 대신 절대 증감, 1,000건당 비율 · 일별 추이에 설정·정책·기준 변경 표시선
- 번호 없는 절 '차단 뒤 재요청'(5절 뒤)·'관측 범위'(9절 뒤), 주요 사건의 같은 패턴 묶음 카드, 11절 '정의·기준'
"""

from __future__ import annotations

import html
import re
from pathlib import Path

from . import aggregate as ag
from . import charts as ch
from . import frame as fr
from . import same_text as st
from .content import CAT_NAMES, FOOTER
from .facts import SECTION_NAMES, Facts, span_text
from .incidents import GRADE_LABELS, NARRATED, Incident, basis_labels, rule_order

TEMPLATE = Path(__file__).with_name("template.html")
SEV_LABEL = {"critical": "높음", "serious": "확인", "warning": "정보", "good": "해당 없음"}
LEVEL_CLS = {"높음": "critical", "중간": "serious", "낮음": "good"}
MAIN_FORMATS = ("DOCX", "XLSX", "PDF", "HWP", "HWPX")      # 형식별 그래프의 고정 줄. 나머지는 '기타'
ACTION_SERIES = [{"key": "BLOCK", "name": "차단", "cls": "block"}, {"key": "MASK", "name": "마스킹", "cls": "mask"},
                 {"key": "ALLOW", "name": "허용", "cls": "allow"}]
LEVEL_SERIES = [{"key": "높음", "name": "높음", "cls": "crit"}, {"key": "중간", "name": "중간", "cls": "serious"},
                {"key": "낮음", "name": "낮음", "cls": "low"}]
MAX_ROWS = 12     # 그래프 한 장의 줄 상한(나머지는 '그 밖')
SEV_ICON = {
    "critical": '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M6 1 L11 10 H1 Z" fill="var(--st-critical)"/></svg>',
    "serious": '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><rect x="1.5" y="1.5" width="9" height="9" rx="1" fill="var(--st-serious)"/></svg>',
    "warning": '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="5" fill="var(--st-warning)"/></svg>',
    "good": '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2 6.5 L5 9 L10 3" stroke="var(--st-good)" stroke-width="2" fill="none"/></svg>',
}
STATUS_SEV = {0: "good", 1: "warning", 2: "critical"}
FUNNEL_LEGEND = [("prev", "검사"), ("secret", "탐지"), ("total", "검사 못 함"), ("block", "차단"), ("mask", "마스킹"),
                 ("crit", "검사 없이 통과"), ("serious", "탐지 후 허용")]


def _e(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _same_cell(d: dict) -> str:
    """보호 문서 상세 '문서와 같은 글자' 칸: 차단 건 중 가장 높은 값(대시보드와 같은 표시) · 대조 불가 건수. 숫자 없으면 '대조 불가'."""
    best, na = d.get("same_max"), d.get("same_na") or 0
    if best is None:
        return st.UNAVAILABLE_LABEL if na else "—"
    return st.format_summary(best) + (f" · {st.UNAVAILABLE_LABEL} {_n(na)}건" if na else "")


def _n(x) -> str:
    return "—" if x is None else f"{int(x):,}"


def _ms(v) -> str:
    if v is None:
        return "기록 없음"
    return f"{v / 1000:.2f}<small>초</small>" if v >= 1000 else f"{v:.0f}<small>ms</small>"


def _ms_plain(v) -> str:
    return f"{v / 1000:.2f}초" if v >= 1000 else f"{v:.0f}ms"


def _share_text(name: str, n: int, total: int) -> str:
    return f"{name} {n:,}건 ({ch.pct(n, total):.1f}%)"


class Ctx:
    def __init__(self, a: dict, fx: Facts, incidents: list[Incident], users: list[dict], issues: list[dict],
                 doc: dict, meta: dict) -> None:
        self.a, self.fx, self.incidents, self.users, self.issues, self.doc, self.meta = \
            a, fx, incidents, users, issues, doc, meta
        if "F_EXPOSED" not in fx:          # facts.build가 넣는다 - 직접 만든 사실 목록이면 여기서 채움
            fr.add_facts(fx, a, incidents)
        self.status = fr.status(fx)
        self.groups = fr.retry_groups(incidents, fr.bypass_pairs(a["events"]))

    # ------------------------------------------------------------ 조각
    def lines(self, block: dict, empty: str = "") -> str:
        items = "".join(f"<li>{_e(x['text'])}</li>" for x in block.get("lines") or [])
        if not items:
            if not empty:
                return ""
            items = f"<li>{_e(empty)}</li>"
        return f'<ul class="brief">{items}</ul>'

    def link(self, lk: dict | None) -> str:
        if not lk:
            return ""
        extra = "".join(f'<span class="lnote">{_e(x)}</span>' for x in (lk.get("note"), lk.get("recent")) if x)
        return (f'<span class="act-wrap"><a class="act" href="{_e(lk["href"])}">{_e(lk["label"])}</a>'
                f'<span class="path mono">{_e(lk["path"])}</span>{extra}</span>')

    def steps_text(self, steps: list[str]) -> str:
        """사건 단계 글 - 사실 목록 안의 문서 번호(D1)는 보고서에서 문서 이름으로 바꿔 쓴다."""
        def name(m):
            f = self.fx.by_id.get(m.group(0))
            return f["label"] if f and f["type"] == "doc" else m.group(0)
        return " → ".join(_e(re.sub(r"(?<![A-Za-z0-9_])D[0-9]+(?![A-Za-z0-9_])", name, s)) for s in steps)

    def user_name(self, uid: str) -> str:
        f = self.fx.get(uid)
        return f'<b>{_e(f["display"])}</b>'

    def period_label(self, which: str = "cur") -> str:
        a = self.a
        if which == "cur":
            return f"{ag.md(a['start'])}–{ag.md(a['end'])}"
        return f"{ag.md(a['prev_start'])}–{ag.md(a['prev_end'])}"

    # ------------------------------------------------------------ 섹션
    def head(self) -> str:
        a, c = self.a, self.a["cur"]["cards"]
        ex = a["excluded"]
        comp = (f"{ag.md(a['prev_start'])}–{ag.md(a['prev_end'])}" if a["comparable"] else "비교 불가(이전 기록 없음)")
        rp = ex.get("resend_prompt") or 0
        excl = (f"시험 {_n(ex['test'])}" + (f" · 시연 문서 {_n(ex['demo'])}" if ex.get("demo") else "")
                + f" · 재전송 {_n(ex['resend'])}" + (f"(질문 재시도 {_n(rp)} 포함)" if rp else "")
                + (f" · 접속 차단 {_n(ex['access'])}" if ex["access"] else ""))
        items = [("sum", "한 장 요약")]
        for n in range(1, 12):
            items.append((f"s{n}", f"{n}. {SECTION_NAMES.get(f'S{n}', '참고') if n < 11 else '참고'}"))
            if n == 5:
                items.append(("bypass", "차단 뒤 재요청"))
            if n == 9:
                items.append(("cov", "관측 범위"))
        toc = "".join(f'<a href="#{k}">{_e(t)}</a>' for k, t in items)
        return f"""
  <header class="head" id="s0">
    <div class="eyebrow">PromptGate · 기간 보고</div>
    <h1>AI 서비스 정보유출 탐지 현황</h1>
    <dl class="meta">
      <div><dt>기간</dt><dd>{a['start'].strftime('%Y.%m.%d')} – {a['end'].strftime('%m.%d')} ({a['days']}일, 한국 시각)</dd></div>
      <div><dt>비교 기간</dt><dd>{_e(comp)}</dd></div>
      <div><dt>검사</dt><dd>{_n(c['total'])}건 <span class="sub">프롬프트 {_n(c['prompt'])} · 파일 {_n(c['file'])}</span></dd></div>
      <div><dt>제외</dt><dd>{_e(excl)}</dd></div>
    </dl>
    <nav class="toc" aria-label="목차">{toc}</nav>
  </header>"""

    # ---- 카드
    def chip(self, value, prev, fmt=None, small: bool = False) -> str:
        return ch.delta_chip(value, prev, comparable=self.a["comparable"], fmt=fmt, small=small)

    def bases(self) -> tuple[int, int | None]:
        """(이번 검사 수, 이전 검사 수 또는 None) - 표본 적음·1,000건당 비율의 분모."""
        t = self.fx.get("F_TOTAL")
        return t["value"], t.get("prev")

    @staticmethod
    def small_tag(small: bool) -> str:
        return ' <span class="smallb">표본 적음</span>' if small else ""

    def kpi(self, fid: str, label: str, sub: str = "", sw: str = "") -> str:
        """요약 카드(설계 v3 A4): 절대값 + 증감(표본 적음이면 % 없이) + 1,000건당 비율(검사 카드 제외, 분모 MIN_BASE 이상만)."""
        f = self.fx.get(fid)
        prev = f.get("prev")
        n, pn = self.bases()
        small = fr.small_base(n, pn)
        prev_line = f'<span class="s">이전 {_n(prev)}</span>' if prev is not None else ""
        swatch = f'<span class="sw" style="background:var(--{sw})"></span>' if sw else ""
        subl = f'<span class="s">{sub}</span>' if sub else ""
        rate = ""
        r = fr.rate_text(f["value"], n) if fid != "F_TOTAL" else None
        if r:
            pr = fr.per1000(prev, pn) if prev is not None and pn is not None else None
            rate = f'<span class="s">{_e(r)}' + (f" · 이전 {pr:,.1f}" if pr is not None else "") + "</span>"
        return (f'<div class="kpi" id="k-{fid}"><span class="l">{swatch}{_e(label)}{self.small_tag(small)}</span>'
                f'<span class="v">{_n(f["value"])}{self.chip(f["value"], prev, small=small or fr.small_prev(prev))}</span>{subl}{rate}{prev_line}</div>')

    def kpi_time(self, fid: str, label: str, value, sub: str, base: tuple[int, int | None] | None = None) -> str:
        """운영 카드(시간·오류 건수) - 사실 목록에 이전 값이 있으면 증감 칩. base = (이번, 이전) 표본 수 → 표본 적음이면 % 없이."""
        f = self.fx.by_id.get(fid)
        prev = f.get("prev") if f else None
        is_time = bool(f) and f["type"] == "time"
        fmt = _ms_plain if is_time else None
        small = prev is not None and base is not None and fr.small_base(base[0], base[1])
        small_n = small or (not is_time and fr.small_prev(prev))      # 이전 건수 1~9건이면 % 없이 절대 증감만(딱지는 검사 수가 적을 때만)
        chip = self.chip(f["value"], prev, fmt, small=small_n) if f and f.get("value") is not None else ""
        prev_line = ""
        if prev is not None:
            prev_line = f'<span class="s">이전 {_e(_ms_plain(prev) if is_time else _n(prev))}</span>'
        return (f'<div class="kpi"><span class="l">{_e(label)}{self.small_tag(small)}</span><span class="v">{value}{chip}</span>'
                f'<span class="s">{sub}</span>{prev_line}</div>')

    # ---- 표
    def table(self, head: list[str], rows: list[list], num_from: int = 1, ids: list[str] | None = None,
              cls: str = "", text_cols: tuple = ()) -> str:
        def num(i: int) -> str:
            return "num" if i >= num_from and i not in text_cols else ""

        th = "".join(f'<th class="{num(i)}">{h}</th>' for i, h in enumerate(head))
        body = []
        for k, r in enumerate(rows):
            rid = f' id="{ids[k]}"' if ids and ids[k] else ""
            body.append(f"<tr{rid}>" + "".join(f'<td class="{num(i)}">{c}</td>' for i, c in enumerate(r)) + "</tr>")
        if not body:
            body = [f'<tr><td colspan="{len(head)}" class="empty">해당 없음</td></tr>']
        return f'<div class="tbl-wrap"><table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'

    # ---- 그래프 (숫자는 집계·사실 목록에서만)
    @staticmethod
    def _act_counts(m: dict) -> dict:
        c = {act: sum(v for (a2, _), v in m["by_action_cat"].items() if a2 == act) for act in ag.ACTIONS}
        c["OTHER"] = m["cards"]["total"] - sum(c.values())
        return c

    def fig_composition(self) -> str:
        a, cur = self.a, self.a["cur"]
        title, sub = "조치 구성", "차단·마스킹·허용 비율"
        total = cur["cards"]["total"]
        if not total:
            return ch.empty_figure("comp", title, sub)
        cc = self._act_counts(cur)
        pc = self._act_counts(a["prev"]) if a["prev"] else None
        series = list(ACTION_SERIES)
        if cc["OTHER"] > 0 or (pc and pc["OTHER"] > 0):
            series.append({"key": "OTHER", "name": "그 밖", "cls": "other"})
        rows = [{"label": "이번 기간", "badge": self.period_label(), "badge_cls": "tm", "values": cc}]
        if pc is not None:
            rows.append({"label": "이전 기간", "badge": self.period_label("prev"), "badge_cls": "tm", "values": pc})
        legend = ch.legend_html([(s["cls"], _share_text(s["name"], cc[s["key"]], total), "box") for s in series
                                 if cc[s["key"]] or s["key"] != "OTHER"])
        desc = " · ".join(_share_text(s["name"], cc[s["key"]], total) for s in series) + f" (검사 {total:,}건)"
        trows = [[r["label"], *[ch.n_fmt(r["values"][s["key"]]) for s in series], ch.n_fmt(sum(r["values"].values()))]
                 for r in rows]
        table = ch.data_table(title, ["기간", *[s["name"] for s in series], "합계"], trows)
        return ch.figure("comp", title, sub, legend, lambda uid, w: ch.hbar_chart(
            uid, title, desc, rows, series, width=w, mode="share"), table)

    def fig_daily(self) -> str:
        a = self.a
        title, sub = "일별 추이", "한국 날짜 · 기록 없는 날 0 · 점선은 이전 기간"
        daily = a["cur"]["daily"]
        days = sorted(daily)
        tot = [sum(daily[d].values()) for d in days]
        if not days or not sum(tot):
            return ch.empty_figure("daily", title, "한국 날짜")
        blk = [daily[d].get("BLOCK", 0) for d in days]
        msk = [daily[d].get("MASK", 0) for d in days]
        alw = [daily[d].get("ALLOW", 0) for d in days]
        pdaily = (a["prev"] or {}).get("daily") or {}
        pdays = sorted(pdaily)
        prev = len(pdays) == len(days) and a["prev"] is not None
        series = [{"key": "total", "name": "검사", "cls": "total", "shape": "circle", "values": tot},
                  {"key": "block", "name": "차단", "cls": "block", "shape": "square", "values": blk},
                  {"key": "mask", "name": "마스킹", "cls": "mask", "shape": "diamond", "values": msk}]
        if prev:
            series[0]["prev"] = [sum(pdaily[d].values()) for d in pdays]
            series[1]["prev"] = [pdaily[d].get("BLOCK", 0) for d in pdays]
            series[2]["prev"] = [pdaily[d].get("MASK", 0) for d in pdays]
        else:
            sub = "한국 날짜 · 기록 없는 날 0"
        marks = fr.change_marks(self.fx, days)
        legend = ch.legend_html([("total", "검사", "line"), ("block", "차단", "line"), ("mask", "마스킹", "line")]
                                + ([("total", "이전 기간(점선)", "dash")] if prev else [])
                                + ([("chg", "설정·정책·기준 변경(번호)", "dash")] if marks else []))
        peak = tot.index(max(tot))
        desc = (f"{ch.md(days[0])}부터 {ch.md(days[-1])}까지 {len(days)}일. 검사 합계 {sum(tot):,}건, "
                f"가장 많은 날 {ch.md(days[peak])} {tot[peak]:,}건" + (", 점선은 이전 기간" if prev else "")
                + (f", 세로 점선은 설정·정책·기준 변경 {len(marks)}곳" if marks else ""))
        chg = [{"i": m["i"], "n": m["n"], "tip": f"{m['md']} " + " · ".join(m["all"])} for m in marks]
        chg_list = ""
        if marks:
            li = "".join(f'<li><b>{m["n"]}</b> {_e(m["md"])} · {_e(" · ".join(m["items"]))}'
                         + (f' 외 {m["more"]}건(8절)' if m["more"] else "") + "</li>" for m in marks)
            chg_list = f'<ul class="chg-list" aria-label="변경 표시선">{li}</ul>'
        head = ["날짜", "검사", "차단", "마스킹", "허용"] + (["이전 기간 날짜", "이전 기간 검사"] if prev else [])
        trows = []
        for i, d in enumerate(days):
            row = [ch.md(d), ch.n_fmt(tot[i]), ch.n_fmt(blk[i]), ch.n_fmt(msk[i]), ch.n_fmt(alw[i])]
            if prev:
                row += [ch.md(pdays[i]), ch.n_fmt(series[0]["prev"][i])]
            trows.append(row)
        table = ch.data_table(title, head, trows, visible=True)
        return ch.figure("daily", title, sub, legend, lambda uid, w: ch.line_chart(
            uid, title, desc, days, series, width=w, prev_days=pdays if prev else None, changes=chg), chg_list + table)

    def fig_funnel(self) -> str:
        """깔때기(설계 v3 A2): 검사 → 탐지·검사 못 함 → 차단·마스킹 → 노출. 숫자는 사실 목록(frame.add_facts)."""
        fx = self.fx
        title, sub = "검사에서 노출까지", "이벤트 1건 단위 · 노출 = 검사 없이 통과 + 탐지 후 허용"
        g = lambda fid: fx.get(fid)["value"]          # noqa: E731
        n = g("F_TOTAL")
        if not n:
            return ch.empty_figure("funnel", title, sub)
        c = self.a["cur"]["cards"]
        rate = fr.rate_text(g("F_EXPOSED"), n)
        stages = [
            {"label": "검사", "parts": [{"name": "검사", "cls": "prev", "value": n}],
             "sub": f"프롬프트 {c['prompt']:,} · 파일 {c['file']:,}"},
            {"label": "탐지·검사 못 함", "parts": [{"name": "탐지", "cls": "secret", "value": g("F_DETECTED")},
                                             {"name": "검사 못 함", "cls": "total", "value": g("F_UNSEEN")}],
             "sub": f"탐지 {g('F_DETECTED'):,} · 검사 못 함 {g('F_UNSEEN'):,}"},
            {"label": "차단·마스킹", "parts": [{"name": "차단", "cls": "block", "value": g("F_BLOCK")},
                                          {"name": "마스킹", "cls": "mask", "value": g("F_MASK")}],
             "sub": f"차단 {g('F_BLOCK'):,} · 마스킹 {g('F_MASK'):,}"},
            {"label": "노출", "parts": [{"name": "검사 없이 통과", "cls": "crit", "value": g("F_UNCHECKED")},
                                      {"name": "탐지 후 허용", "cls": "serious", "value": g("F_DET_ALLOW")}],
             "sub": f"검사 없이 통과 {g('F_UNCHECKED'):,} · 탐지 후 허용 {g('F_DET_ALLOW'):,}" + (f" · {rate}" if rate else "")},
        ]
        legend = ch.legend_html([(cls, name, "box") for cls, name in FUNNEL_LEGEND])
        desc = (f"검사 {n:,}건 → 탐지·검사 못 함 {g('F_ATTN'):,}건 → 차단·마스킹 {g('F_INTERVENED'):,}건, "
                f"노출 {g('F_EXPOSED'):,}건")
        pn = fx.get("F_TOTAL").get("prev")

        def row(name, fid, indent=False):
            f = fx.get(fid)
            p = f.get("prev")
            r = fr.per1000(f["value"], n)
            per = "—" if fid == "F_TOTAL" else (f"{r:,.1f}" if r is not None else "표본 적음")
            return [("└ " if indent else "") + name, ch.n_fmt(f["value"]), fr.NO_PREV if p is None else ch.n_fmt(p), per]

        trows = [row("검사", "F_TOTAL"), row("탐지·검사 못 함", "F_ATTN"), row("탐지", "F_DETECTED", True),
                 row("검사 못 함", "F_UNSEEN", True), row("차단·마스킹", "F_INTERVENED"), row("차단", "F_BLOCK", True),
                 row("마스킹", "F_MASK", True), row("노출", "F_EXPOSED"), row("검사 없이 통과", "F_UNCHECKED", True),
                 row("탐지 후 허용", "F_DET_ALLOW", True), row("문제 없음 허용", "F_ALLOW")]
        table = ch.data_table(title, ["단계", "이번 기간", "이전 기간", "1,000건당"], trows, visible=True)
        line = f'<p class="note fl">{_e(fr.funnel_line(fr.funnel_counts(self.a["events"])))}</p>'
        return ch.figure("funnel", title, sub, legend, lambda uid, w: ch.funnel_chart(
            uid, title, desc, stages, width=w), line + table)

    def fig_services(self) -> str:
        cur = self.a["cur"]
        title, sub = "서비스별 조치", "이벤트 1건 단위"
        known = list(ag.SERVICE_IDS)
        names = [s for s in known if any(cur["by_svc"].get((s, act), 0) for act in ag.ACTIONS)]
        names += sorted({s for (s, _) in cur["by_svc"]} - set(known))
        rows = [{"label": s, "values": {act: cur["by_svc"].get((s, act), 0) for act in ag.ACTIONS}} for s in names]
        rows = [r for r in rows if sum(r["values"].values())]
        if not rows:
            return ch.empty_figure("svc", title, sub)
        legend = ch.legend_html([(s["cls"], s["name"], "box") for s in ACTION_SERIES])
        grand = sum(sum(r["values"].values()) for r in rows)
        desc = " · ".join(f"{r['label']} {sum(r['values'].values()):,}건" for r in rows) + f" (검사 {grand:,}건)"
        trows = [[r["label"], *[ch.n_fmt(r["values"][act]) for act in ag.ACTIONS], ch.n_fmt(sum(r["values"].values()))]
                 for r in rows]
        table = ch.data_table(title, ["서비스", *[s["name"] for s in ACTION_SERIES], "합계"], trows)
        return ch.figure("svc", title, sub, legend, lambda uid, w: ch.hbar_chart(
            uid, title, desc, rows, ACTION_SERIES, width=w, mode="stack"), table)

    def fig_pii(self) -> str:
        cur = self.a["cur"]
        title, sub = "유형별 처리", "건 = 그 유형이 나온 이벤트"
        items = cur["pii"]
        if not items:
            return ch.empty_figure("pii", title, sub)
        shown, rest = items[:MAX_ROWS], items[MAX_ROWS:]
        rows = [{"label": p["name"], "badge": "인증정보" if p["cred"] else None,
                 "tip": f"값 {p['values']:,}개", "values": {act: p[act] for act in ag.ACTIONS}} for p in shown]
        if rest:
            rows.append({"label": f"그 밖 {len(rest)}종", "values": {act: sum(p[act] for p in rest) for act in ag.ACTIONS}})
        legend = ch.legend_html([(s["cls"], s["name"], "box") for s in ACTION_SERIES])
        desc = " · ".join(f"{r['label']} {sum(r['values'].values()):,}건" for r in rows)
        trows = [[r["label"], *[ch.n_fmt(r["values"][act]) for act in ag.ACTIONS], ch.n_fmt(sum(r["values"].values()))]
                 for r in rows]
        table = ch.data_table(title, ["유형", *[s["name"] for s in ACTION_SERIES], "합계"], trows)
        return ch.figure("pii", title, sub, legend, lambda uid, w: ch.hbar_chart(
            uid, title, desc, rows, ACTION_SERIES, width=w, mode="stack"), table)

    def fig_formats(self) -> str:
        cur = self.a["cur"]
        title, sub = "파일 형식별 처리", "형식 = 판정 기록 파일 확장자 · 그 밖은 기타"
        fm = cur["formats"]
        if not sum(fm.values()):
            return ch.empty_figure("fmt", title, sub)
        rows, others = [], {}
        for name in MAIN_FORMATS:
            rows.append({"label": name, "values": {act: fm.get((name, act), 0) for act in ag.ACTIONS}})
        etc = {act: 0 for act in ag.ACTIONS}
        for (f, act), v in fm.items():
            if f not in MAIN_FORMATS:
                etc[act] = etc.get(act, 0) + v
                others[f] = others.get(f, 0) + v
        tip = " · ".join(f"{k} {v}" for k, v in sorted(others.items(), key=lambda kv: (-kv[1], kv[0]))) or None
        rows.append({"label": "기타", "tip": tip, "values": etc})
        legend = ch.legend_html([(s["cls"], s["name"], "box") for s in ACTION_SERIES])
        grand = sum(sum(r["values"].values()) for r in rows)
        desc = " · ".join(f"{r['label']} {sum(r['values'].values()):,}건" for r in rows) + f" (파일 {grand:,}건)"
        trows = [[r["label"], *[ch.n_fmt(r["values"][act]) for act in ag.ACTIONS], ch.n_fmt(sum(r["values"].values()))]
                 for r in rows]
        table = ch.data_table(title, ["형식", *[s["name"] for s in ACTION_SERIES], "합계"], trows)
        return ch.figure("fmt", title, sub, legend, lambda uid, w: ch.hbar_chart(
            uid, title, desc, rows, ACTION_SERIES, width=w, mode="stack"), table)

    def fig_docs(self) -> str:
        a, cur = self.a, self.a["cur"]
        title = "보호 문서별 차단"
        docs = cur["docs"]
        if not docs:
            return ch.empty_figure("docs", title, "문서 0종")
        new = set(ag.new_docs(a))
        prev_n = {d["doc"]: d["n"] for d in (a["prev"] or {}).get("docs", [])}
        has_prev = a["prev"] is not None
        shown, rest = docs[:MAX_ROWS], docs[MAX_ROWS:]
        series = [{"key": "cur", "name": "이번 기간", "cls": "secret"}] + \
                 ([{"key": "prev", "name": "이전 기간", "cls": "prev"}] if has_prev else [])
        rows = [{"label": d["doc"], "badge": "새로 차단" if d["doc"] in new else None,
                 "values": {"cur": d["n"], "prev": prev_n.get(d["doc"], 0)}} for d in shown]
        if rest:
            rows.append({"label": f"그 밖 {len(rest)}종", "values": {"cur": sum(d["n"] for d in rest),
                                                                     "prev": sum(prev_n.get(d["doc"], 0) for d in rest)}})
        legend = ch.legend_html([(s["cls"], s["name"], "box") for s in series])
        sub = f"문서 {len(docs):,}종 · 새로 차단 {len(new):,}종" if has_prev else f"문서 {len(docs):,}종"
        desc = " · ".join(f"{r['label']} {r['values']['cur']:,}건" + (" (새로 차단)" if r.get("badge") else "") for r in rows)
        head = ["문서", "이번 기간"] + (["이전 기간", "새로 차단"] if has_prev else [])
        trows = [[r["label"], ch.n_fmt(r["values"]["cur"])] + ([ch.n_fmt(r["values"]["prev"]), "예" if r.get("badge") else "아니오"]
                                                               if has_prev else []) for r in rows]
        table = ch.data_table(title, head, trows)
        return ch.figure("docs", title, sub, legend, lambda uid, w: ch.hbar_chart(
            uid, title, desc, rows, series, width=w, mode="group"), table)

    def fig_risk(self) -> str:
        title, sub = "사용자 위험 분포", "등급별 사용자 수 · 식별된 사용자만"
        counts = {s["key"]: 0 for s in LEVEL_SERIES}
        for u in self.users:
            counts[self.doc["levels"].get(u["id"], u["rule_level"])] += 1
        if not sum(counts.values()):
            return ch.empty_figure("risk", title, sub)
        rows = [{"label": s["name"], "values": {s["key"]: counts[s["key"]]}} for s in LEVEL_SERIES]
        desc = " · ".join(f"{k} {v:,}명" for k, v in counts.items()) + f" (식별 사용자 {sum(counts.values()):,}명)"
        table = ch.data_table(title, ["등급", "사용자"], [[k, ch.n_fmt(v)] for k, v in counts.items()])
        return ch.figure("risk", title, sub, "", lambda uid, w: ch.hbar_chart(
            uid, title, desc, rows, LEVEL_SERIES, width=w, mode="stack", unit="명"), table)

    def fig_content(self, c: dict) -> str:
        title, sub = "내용 범주별 건수", "마스킹은 표본 기준 · 기밀 차단은 전체"
        data = [r for r in c["rows"] if r["mask"] or r["secret"]]
        if not data:
            return ch.empty_figure("content", title, sub)
        series = [{"key": "mask", "name": "마스킹 표본", "cls": "mask"}, {"key": "secret", "name": "기밀 차단", "cls": "secret"}]
        rows = [{"label": r["name"], "values": {"mask": r["mask"], "secret": r["secret"]}} for r in data]
        legend = ch.legend_html([(s["cls"], s["name"], "box") for s in series])
        desc = " · ".join(f"{r['label']} 마스킹 {r['values']['mask']:,}건 기밀 차단 {r['values']['secret']:,}건" for r in rows)
        table = ch.data_table(title, ["범주", "마스킹 표본", "기밀 차단"],
                              [[r["label"], ch.n_fmt(r["values"]["mask"]), ch.n_fmt(r["values"]["secret"])] for r in rows])
        return ch.figure("content", title, sub, legend, lambda uid, w: ch.hbar_chart(
            uid, title, desc, rows, series, width=w, mode="group"), table)

    # ---- 한 장 요약 (설계 v3 A1·A2·A3·A5 한 줄, A9 요약 쪽) - 번호 없음, 인쇄하면 첫 쪽
    def onepage(self) -> str:
        fx, a, st = self.fx, self.a, self.status
        lv = "na" if st["level"] is None else str(st["level"])
        icon = SEV_ICON[STATUS_SEV[st["level"]]] if st["level"] is not None else ""
        small = self.small_tag(st["small"] and bool(st["total"]))
        changes, note = fr.change_clauses(fx, a["comparable"])
        ch_items = "".join(f"<li>{_e(x)}</li>" for x in changes)
        ch_html = (f'<div class="chg"><span class="k">이전 대비</span><ul>{ch_items}</ul>'
                   f'<span class="s">{_e(note)}</span></div>') if ch_items else \
            f'<div class="chg"><span class="k">이전 대비</span><span class="s">{_e(note)}</span></div>'
        frows = []
        for f in st["flags"]:
            flv = "확인 불가" if f.get("level") is None else fr.STATUS_LABELS[f["level"]]
            cls = "na" if f.get("level") is None else str(f["level"])
            val = fr.flag_value_text(f).split(" · ", 1)
            val_html = _e(val[0]) + (f'<br><small class="muted">{_e(val[1])}</small>' if len(val) > 1 else "")
            frows.append([f'{_e(f["label"])}<br><small class="muted">{_e(f["sub"])}</small>',
                          f'<span class="flv lv{cls}">{_e(flv)}</span>', val_html, _e(fr.flag_rule_text(f))])
        flags = self.table(["판단 항목", "단계", "이번 기간", "기준(우리 설정값)"], frows, num_from=9, cls="wrap flags")
        live = [r for r in self.issues if not r["off"]]
        by_lv: dict[str, list[str]] = {}
        for r in live:
            by_lv.setdefault(r["level"], []).append(r["name"])
        recs = " · ".join(f"{lvl} {len(names)}({' · '.join(names)})" for lvl, names in by_lv.items()) or "없음"
        heads = [
            ("관측 범위", fr.coverage_headline(a, fx), "#cov", "관측 범위 보기"),
            ("차단 뒤 재요청", self.bypass_line(), "#bypass", "묶음 보기"),
            ("조치 권고", f"{len(live)}건 · {recs}", "#s10", "10. 권고·다음 조치"),
        ]
        hl = "".join(f'<li><span class="k">{_e(k)}</span><span>{_e(v)}</span><a href="{h}">{_e(t)}</a></li>'
                     for k, v, h, t in heads)
        comp = (f"비교 {self.period_label('prev')}" if a["comparable"] else "비교 불가(이전 기록 없음)")
        return f"""
  <section aria-labelledby="sumh" id="sum" class="onepage">
    <div class="sec-head"><h2 id="sumh">한 장 요약</h2><span class="sub">{_e(self.period_label())} · {_e(comp)}</span></div>
    <div class="verdict lv{lv}">
      <div class="st">{icon}<span>{_e(st['label'])}</span>{small}</div>
      <div class="vbody">
        <p class="lead">{_e(fr.lead_sentence(self.period_label(), fx))}</p>
        {ch_html}
      </div>
    </div>
    {flags}
    {self.fig_funnel()}
    <ul class="heads">{hl}</ul>
    <p class="foot-rule">{_e(fr.status_rule_line())} · 용어 정의는 11. 참고</p>
  </section>
  <p class="part-label" id="body">본문</p>"""

    # ---- 1. 요약
    def s1(self) -> str:
        c = self.a["cur"]["cards"]
        unchk = " · ".join(f"{ag.RC_LABELS.get(rc, rc)} {n}" for rc, n in self.a["cur"]["unchecked_by_rc"].most_common())
        rest = (f'<p class="note">그 밖 {_n(c["rest"])}건(카드 밖 조치·사유 조합)</p>' if c["rest"] else "")
        return f"""
  <section aria-labelledby="s1h" id="s1">
    <div class="sec-head"><h2 id="s1h">1. 요약</h2></div>
    <div class="kpis">
      {self.kpi("F_TOTAL", "검사", f"프롬프트 {_n(c['prompt'])} · 파일 {_n(c['file'])}")}
      {self.kpi("F_SECRET", "기밀 차단", f"문서 일치 {_n(c['secret_doc'])} · 키워드 {_n(c['secret_kw'])}", "s1")}
      {self.kpi("F_MASK", "개인정보 마스킹", "", "s3")}
      {self.kpi("F_PII_BLOCK", "개인정보 차단", f"마스킹 실패 {_n(c['mask_failed'])}", "s2")}
      {self.kpi("F_UNINSP_BLOCK", "검사 불가 차단", "", "s2")}
      {self.kpi("F_UNCHECKED", "검사 없이 통과", _e(unchk))}
    </div>
    <p class="note">문제 없음 허용 {_n(c['allow_clean'])}건 · 카드 합 + 허용 = 검사 {_n(c['total'])}건</p>{rest}
    {self.lines(self.doc["summary"])}
    {self.fig_composition()}
  </section>"""

    # ---- 2. 판정 현황
    def s2(self) -> str:
        cur = self.a["cur"]
        cats = sorted({cat for (_, cat) in cur["by_action_cat"]}, key=lambda c: list(ag.CAT_LABELS).index(c))
        rows = [[_e(ag.CAT_LABELS[cat])] + [_n(cur["by_action_cat"].get((act, cat), 0)) for act in ag.ACTIONS]
                + [_n(sum(cur["by_action_cat"].get((act, cat), 0) for act in ag.ACTIONS))] for cat in cats]
        rows.append(["<b>합계</b>"] + [f"<b>{_n(sum(v for (a2, _), v in cur['by_action_cat'].items() if a2 == act))}</b>"
                                       for act in ag.ACTIONS] + [f"<b>{_n(cur['cards']['total'])}</b>"])
        paths = sorted({p for (p, _) in cur["by_path"]})
        prow = [[_e(ag.CT_LABELS.get(p, p or "기록 없음"))] + [_n(cur["by_path"].get((p, act), 0)) for act in ag.ACTIONS]
                for p in paths]
        acts = [ag.ACTION_LABELS[x] for x in ag.ACTIONS]
        return f"""
  <section aria-labelledby="s2h" id="s2">
    <div class="sec-head"><h2 id="s2h">2. 판정 현황</h2></div>
    {self.lines(self.doc["commentary"]["S2"])}
    {self.fig_daily()}
    {self.fig_services()}
    <div class="chart">
      <div class="chart-title"><h3>조치 × 사유</h3><span class="sub">이벤트 1건 단위</span></div>
      {self.table(["사유", *acts, "합계"], rows)}
    </div>
    <div class="chart"><div class="chart-title"><h3>경로별</h3></div>{self.table(["경로", *acts], prow)}</div>
  </section>"""

    # ---- 3. 기밀정보
    def s3(self) -> str:
        a, cur = self.a, self.a["cur"]
        fx = self.fx
        new = set(ag.new_docs(a))
        prev_n = {d["doc"]: d["n"] for d in (a["prev"] or {}).get("docs", [])}
        docs = fx.ids(lambda f: f["type"] == "doc")
        rows, ids = [], []
        for did in docs:
            f = fx.get(did)
            d = next(x for x in cur["docs"] if x["doc"] == f["label"])
            span = ag.kst_md(d["first"]) if ag.kst_md(d["first"]) == ag.kst_md(d["last"]) else f"{ag.kst_md(d['first'])}–{ag.kst_md(d['last'])}"
            rows.append([f'<span class="mono">{_e(f["label"])}</span>' + (' <span class="badge">새로 차단</span>' if f["label"] in new else ""),
                         _n(d["n"]), _n(prev_n.get(f["label"], 0)) if a["prev"] else "—", _n(d["days"]), span,
                         _same_cell(d)])
            ids.append(f"doc-{did}")
        reg = [d for d in a["documents"] if d.get("status") == "active"]
        by_fmt = {}
        for d in reg:
            by_fmt[(d.get("format") or "기타").upper()] = by_fmt.get((d.get("format") or "기타").upper(), 0) + 1
        reg_txt = " · ".join(f"{k} {v}" for k, v in sorted(by_fmt.items())) or "없음"
        kw = fx.by_id.get("F_KW_APPROVED")
        kw_txt = (f"승인 키워드 {_n(kw['value'])}개 · 승인 대기 {_n(fx.get('F_KW_PENDING')['value'])}개" if kw
                  else "키워드 수 확인 실패")
        hit = len(cur["docs"])
        return f"""
  <section aria-labelledby="s3h" id="s3">
    <div class="sec-head"><h2 id="s3h">3. 기밀정보</h2></div>
    {self.lines(self.doc["commentary"]["S3"])}
    {self.fig_docs()}
    <div class="chart">
      <div class="chart-title"><h3>보호 문서 상세</h3><span class="sub">문서와 같은 글자 = 차단 건 중 가장 높은 값(대시보드와 같은 값)</span></div>
      {self.table(["문서", "차단", "이전", "활동일", "기간", "문서와 같은 글자"], rows, num_from=1, ids=ids)}
    </div>
    <ul class="facts">
      <li>기밀 키워드 차단 {_n(cur['cards']['secret_kw'])}건 · 어떤 키워드인지는 기록 없음</li>
      <li>등록 문서 {_n(len(reg))}종({_e(reg_txt)}) · 기간 중 차단된 문서 {_n(hit)}/{_n(len(reg))}</li>
      <li>{_e(kw_txt)}</li>
    </ul>
  </section>"""

    # ---- 4. 개인정보·인증정보
    def s4(self) -> str:
        cur = self.a["cur"]
        rows = [[_e(p["name"]), "인증정보" if p["cred"] else "개인정보", _n(p["items"]), _n(p["values"]), _n(p["MASK"]),
                 _n(p["BLOCK"]), _n(p["ALLOW"])] for p in cur["pii"]]
        fmts = sorted({f for (f, _) in cur["formats"]})
        frow = [[_e(f)] + [_n(cur["formats"].get((f, act), 0)) for act in ag.ACTIONS] for f in fmts]
        return f"""
  <section aria-labelledby="s4h" id="s4">
    <div class="sec-head"><h2 id="s4h">4. 개인정보·인증정보</h2></div>
    {self.lines(self.doc["commentary"]["S4"])}
    {self.fig_pii()}
    {self.fig_formats()}
    <div class="grid2">
      <div class="chart"><div class="chart-title"><h3>유형 상세</h3><span class="sub">건 = 그 유형이 나온 이벤트, 개 = 값 개수</span></div>
        {self.table(["유형", "구분", "건", "개", "마스킹", "차단", "허용"], rows, num_from=2)}</div>
      <div class="chart"><div class="chart-title"><h3>파일 형식 상세</h3><span class="sub">형식 = 판정 기록 파일 확장자</span></div>
        {self.table(["형식", *[ag.ACTION_LABELS[x] for x in ag.ACTIONS]], frow)}</div>
    </div>
  </section>"""

    # ---- 5. 주요 사건
    def inc_link(self, inc: Incident) -> str:
        from .compose import build_link
        if inc.user:
            return self.link(build_link("USER_EVENTS", inc.user, self.fx, self.a, "R1"))
        docs = self.fx.get(inc.id).get("docs") or []
        if docs:
            return self.link(build_link("DOC_EVENTS", docs[0], self.fx, self.a, "R1"))
        return ""

    def inc_card(self, inc: Incident, rank: int) -> str:
        f = self.fx.get(inc.id)
        n = self.doc["narr"].get(inc.id) or {}
        body = "".join(f"<li>{_e(x['text'])}</li>" for x in n.get("course") or [])
        for key, label in (("result", "결과"), ("risk", "위험")):
            if n.get(key):
                body += f'<li><span class="k">{label}</span> {_e(n[key]["text"])}</li>'
        who = self.user_name(inc.user) if inc.user else "미식별 사용자"
        steps = self.steps_text(f["steps"])
        return f"""
      <article class="inc g{inc.grade}" id="card-{inc.id}">
        <div class="inc-top"><span class="rank">{rank}</span><h3>사건 {inc.id[1:]}</h3><span class="grade">{_e(GRADE_LABELS[inc.grade])}</span>
          <span class="meta-i">{who} · {_e(' · '.join(inc.services))} · {_e(f['start'])} · {_e(span_text(inc.span_min))} · 요청 {len(inc.members)}</span></div>
        <ul class="brief">{body}</ul>
        <div class="steps">{steps}</div>
        {self.inc_link(inc)}
      </article>"""

    def time_range(self, start, end) -> str:
        a, b = ag.kst_hm(start), ag.kst_hm(end)
        if a == b:
            return a
        return f"{a}–{b.split(' ', 1)[1]}" if a.split(" ")[0] == b.split(" ")[0] else f"{a}–{b}"

    def group_card(self, ids: list[str], ranks: dict[str, int], by_id: dict[str, Incident]) -> str:
        """같은 패턴 사건 묶음 카드(설계 v3 A5) - 사건별 카드(번호·링크 그대로)는 안쪽 <details>."""
        incs = [by_id[i] for i in ids]
        first = incs[0]
        ident = [i for i in incs if i.ident]
        users = list(dict.fromkeys(i.user for i in ident if i.user))
        if len(users) == 1 and len(ident) == len(incs):
            who = self.user_name(users[0])
        else:
            who = f"식별 {len(ident)} · 미식별 {len(incs) - len(ident)}"
        svcs = list(dict.fromkeys(s for i in incs for s in i.services))
        grade = min(i.grade for i in incs)
        span = self.time_range(min(i.start for i in incs), max(i.end for i in incs))
        members = " · ".join(f'<a href="#card-{i.id}">{i.id[1:]}</a>' for i in incs)
        inner = "".join(self.inc_card(i, ranks[i.id]) for i in incs)
        return f"""
      <article class="inc grp g{grade}" id="grp-{first.id}">
        <div class="inc-top"><span class="rank">{'·'.join(str(ranks[i.id]) for i in incs[:4])}{'…' if len(incs) > 4 else ''}</span><h3>같은 패턴 사건 {len(incs)}건</h3><span class="grade">{_e(GRADE_LABELS[grade])}</span>
          <span class="meta-i">{who} · {_e(' · '.join(svcs))} · {_e(span)} · 요청 {sum(len(i.members) for i in incs)}</span></div>
        <div class="steps">{self.steps_text(self.fx.get(first.id)["steps"])}</div>
        <p class="grp-ids">사건 {members}</p>
        {self.inc_link(first)}
        <details class="grp-more"><summary>사건별 카드 {len(incs)}건</summary><div class="incs">{inner}</div></details>
      </article>"""

    def s5(self) -> str:
        fx, doc = self.fx, self.doc
        if not self.incidents:
            body = '<p class="note">해당 없음</p>'
            return f'<section aria-labelledby="s5h" id="s5"><div class="sec-head"><h2 id="s5h">5. 주요 사건</h2></div>{body}</section>'
        by_id = {i.id: i for i in self.incidents}
        narrated = doc["order"][:NARRATED]
        ranks = {iid: k for k, iid in enumerate(narrated, 1)}
        packs = fr.same_pattern(narrated, {iid: fx.get(iid)["steps"] for iid in narrated}, by_id)
        cards = [self.inc_card(by_id[p[0]], ranks[p[0]]) if len(p) == 1 else self.group_card(p, ranks, by_id) for p in packs]
        grouped = sum(len(p) for p in packs if len(p) > 1)
        grp_note = (f'<p class="note">같은 패턴 사건 = 단계 글과 첫 대상이 같은 사건 · {len([p for p in packs if len(p) > 1])}묶음 '
                    f'{grouped}건을 카드 하나로 묶음(사건별 카드는 펼쳐 보기)</p>') if grouped else ""
        rows, ids = [], []
        for inc in rule_order(self.incidents):
            f = fx.get(inc.id)
            who = self.user_name(inc.user) if inc.user else "미식별"
            num = inc.id[1:]
            rows.append([f'<a href="#card-{inc.id}">{num}</a>' if inc.id in doc["order"][:NARRATED] else num,
                         _e(GRADE_LABELS[inc.grade]), who, _e(" · ".join(inc.services)), _e(f["start"]),
                         _e(span_text(inc.span_min)), _n(len(inc.members)), _n(inc.count("BLOCK")), _n(inc.count("MASK")),
                         _n(inc.count("ALLOW")), self.steps_text(f["steps"])])
            ids.append(f"inc-{inc.id}")
        g = {k: sum(1 for i in self.incidents if i.grade == k) for k in GRADE_LABELS}
        gtxt = " · ".join(f"{GRADE_LABELS[k]} {v}" for k, v in g.items() if v)
        unk = sum(1 for i in self.incidents if not i.ident)
        return f"""
  <section aria-labelledby="s5h" id="s5">
    <div class="sec-head"><h2 id="s5h">5. 주요 사건</h2></div>
    <p class="note">사건 {_n(len(self.incidents))}건 · 상세 {_n(min(NARRATED, len(doc['order'])))}건 · {_e(gtxt)} · 미식별 {_n(unk)}건(같은 서비스·같은 대상만 묶음)</p>
    {grp_note}
    <div class="incs">{''.join(cards)}</div>
    <div class="inc-all">
      {self.table(["사건", "등급", "사용자", "서비스", "시작", "길이", "요청", "차단", "마스킹", "허용", "단계"], rows, num_from=6, ids=ids, cls="wrap", text_cols=(10,))}
    </div>
    <p class="note">사건 = 같은 사용자 같은 대상 30분 간격, 차단 뒤 10분 안 같은 서비스 요청. '차단 뒤 결과 바뀜'은 같은 내용인지 모름(원문 안 봄)</p>
  </section>"""

    # ---- 차단 뒤 재요청 (설계 v3 A5) - 번호 없음, 5절 뒤
    def user_link(self, uid: str) -> str:
        """사용자 조치 링크 - 6절과 같은 규칙(등급 높음·중간 + 기밀·인증정보면 '이 사용자 차단', 아니면 '사용자 기록 보기').
        접속 차단 화면 반영 전에는 build_link가 사용자 기록 링크로 바꾼다(REPORT_ACCESS_BLOCK_LINK)."""
        from .compose import build_link
        u = next(x for x in self.users if x["id"] == uid)
        level = self.doc["levels"].get(uid, u["rule_level"])
        act = "BLOCK_USER" if level in ("높음", "중간") and (u["secret"] or u["cred"]) else "USER_EVENTS"
        return self.link(build_link(act, uid, self.fx, self.a, "R1" if u["secret"] else "R3"))

    def bypass_line(self) -> str:
        n, users = fr.bypass_episodes(self.a["events"])
        return fr.bypass_headline(n, users, self.groups)

    def s_bypass(self) -> str:
        from .compose import build_link
        fx = self.fx
        head = '<section aria-labelledby="bypassh" id="bypass">\n    <div class="sec-head"><h2 id="bypassh">차단 뒤 재요청</h2></div>'
        defn = ("<p class=\"note\">차단 뒤 재요청 = 사건 안 첫 차단 뒤 요청이 있는 사건, 첫 차단의 대상별 묶음 · "
                "차단 뒤 통과 = 식별 사용자가 차단된 뒤 10분 안 같은 서비스에서 허용된 요청을 받은 횟수(차단→허용 쌍마다 1, 같은 내용인지는 모름, 원문 안 봄) · "
                "미식별은 사람을 가를 수 없어 차단 뒤 요청을 묶지 않음</p>")
        if not self.groups:
            return f'\n  {head}\n    <p class="note">해당 없음</p>\n    {defn}\n  </section>'
        doc_ids = {fx.get(d)["label"]: d for d in fx.ids(lambda f: f["type"] == "doc")}
        cards = []
        for k, g in enumerate(self.groups[:fr.MAX_GROUPS], 1):
            ids = " · ".join(f'<a href="#inc-{i}">{i[1:]}</a>' for i in g["ids"])
            acts = []
            if g["cat"] == "doc" and g["docs"] and g["docs"][0] in doc_ids:
                acts.append(self.link(build_link("DOC_EVENTS", doc_ids[g["docs"][0]], fx, self.a, "R1")))
            for uid in g["users"]:
                acts.append(f'<span class="who">{self.user_name(uid)} {self.user_link(uid)}</span>')
            cards.append(f"""
      <article class="bp{' passed' if g['passed'] else ''}" id="bp-{k}">
        <div class="inc-top"><h3>{_e(g['label'])}</h3><span class="grade">{_e(ag.CAT_LABELS.get(g['cat'], g['cat']))}</span></div>
        <p class="bp-line">{_e(fr.group_line(g))}</p>
        <p class="grp-ids">사건 {ids} · {_e(self.time_range(g['start'], g['end']))}</p>
        <div class="bp-acts">{''.join(acts)}</div>
      </article>""")
        rest = self.groups[fr.MAX_GROUPS:]
        more = (f'<p class="note">외 {len(rest)}묶음(사건 {sum(g["n"] for g in rest)}건)은 줄여 보였습니다. 전체 사건은 5절 표에 있습니다</p>'
                if rest else "")
        return f"""
  {head}
    <p class="note">{_e(self.bypass_line())}</p>
    <div class="incs">{''.join(cards)}</div>
    {more}
    {defn}
  </section>"""

    # ---- 6. 사용자별 위험
    def s6(self) -> str:
        fx, doc = self.fx, self.doc
        unident = self.a["cur"]["unident"]
        if not self.users:
            return (f'<section aria-labelledby="s6h" id="s6"><div class="sec-head"><h2 id="s6h">6. 사용자별 위험</h2></div>'
                    f'<p class="note">식별된 사용자 없음(식별 안 됨 {_n(unident)}건)</p></section>')
        rows, ids = [], []
        for u in self.users:
            uid = u["id"]
            level = doc["levels"].get(uid, u["rule_level"])
            t = doc["user_text"].get(uid) or {}
            why = "".join(f"<div>{_e(x['text'])}</div>" for x in t.get("lines") or [])
            if not why:
                why = f'<div class="muted">{_e(basis_labels(u))}</div>'
            incs = ", ".join(f'<a href="#inc-{i}">{i[1:]}</a>' for i in u["incidents"]) or "—"
            client = fx.get(uid)["client"]
            rows.append([f'{self.user_name(uid)}<br><small class="mono muted">{_e(client)}</small>',
                         f'<span class="lv {LEVEL_CLS[level]}">{_e(level)}</span>', why, incs,
                         _n(u["events"]), self.user_link(uid)])
            ids.append(f"user-{uid}")
        return f"""
  <section aria-labelledby="s6h" id="s6">
    <div class="sec-head"><h2 id="s6h">6. 사용자별 위험</h2></div>
    <p class="note">식별 사용자 {_n(len(self.users))}명 · 식별 안 됨 {_n(unident)}/{_n(self.a['cur']['cards']['total'])}건(평가 안 함) · 등급은 보고용 참고값</p>
    {self.fig_risk()}
    {self.table(["사용자", "등급", "이유", "사건", "검사", "조치"], rows, num_from=4, ids=ids, cls="wrap", text_cols=(5,))}
  </section>"""

    # ---- 7. 내용 경향
    def doc_table(self) -> str:
        rows = [[_e(d["doc"]), _n(d["n"])] for d in self.a["cur"]["docs"]]
        return self.table(["보호 문서", "기밀 차단"], rows)

    def s7(self) -> str:
        c = self.doc["content"]
        state = self.meta.get("content_state", "off")
        if c.get("rows"):
            rows, ids = [], []
            for r in c["rows"]:
                subs = " · ".join(f"{_e(s)} {n}" for s, n in r["top_subs"]) or "—"
                task = " · ".join(f"{_e(s)} {n}" for s, n in r["top_task"]) or "—"
                rows.append([_e(r["name"]), _n(r["mask"]), _n(r["secret"]), subs, task])
                ids.append(f"cat-{r['cat']}")
            fail = f" · 분류 실패 {_n(c['failed'])}" if c.get("failed") else ""
            doccat = "" if c.get("doc_cats_known") else " · 보호 문서 범주 확인 실패"
            body = (self.lines(self.doc["commentary"].get("S7") or {"lines": []})
                    + self.fig_content(c)
                    + self.table(["범주", "마스킹 표본", "기밀 차단", "주요 하위 유형", "주요 요청 형태"], rows, num_from=1, ids=ids, cls="wrap")
                    + f'<p class="note">표본 {_n(c["sample"])}/{_n(c["pool"])}건 · {FOOTER}{fail}{doccat}</p>')
        else:
            # 꺼진 이유가 LLM·GPU 때문이어도 보고서에는 쓰지 않는다(생성 기록 JSON에 이유가 남는다)
            msg = {"off": "내용 경향 꺼짐", "off_global": "내용 경향 꺼짐(관리자 설정)", "no_llm": "내용 경향 꺼짐",
                   "no_sample": "표본 없음(글이 저장된 마스킹 0건)",
                   "failed": "내용 경향 분류 안 함(분류 실패)"}.get(state if state != "on" else c.get("state", "off"), "내용 경향 꺼짐")
            body = f'<p class="note">{_e(msg)}</p>' + self.doc_table()
        return f"""
  <section aria-labelledby="s7h" id="s7">
    <div class="sec-head"><h2 id="s7h">7. 내용 경향</h2></div>
    {body}
  </section>"""

    # ---- 8. 설정·정책 변경
    def s8(self) -> str:
        a, fx = self.a, self.fx
        adm = a["admin"]
        by = [[_e(ag.ADMIN_ACTION_LABELS.get(k, k)), _n(v)] for k, v in adm["by_action"].most_common()]
        recent = [[_e(ag.kst_hm(r["occurred_at"])), _e(r["admin_id"]), _e(ag.ADMIN_ACTION_LABELS.get(r["action"], r["action"])),
                   _e(r["target_type"]), "성공" if r["result"] == "SUCCESS" else "실패"] for r in adm["ops"][-20:]]
        changes = fx.ids(lambda f: f["type"] == "change")
        crow = [[_e(fx.get(f)["at"]), _e(fx.get(f)["label"]),
                 _e(f"{fx.get(f).get('before') or '—'} → {fx.get(f).get('after') or '—'}" if "before" in fx.get(f) else (fx.get(f).get("kind") or ""))]
                for f in changes]
        gw = "" if a["gateway"]["saved"] else "<li>Gateway 설정: 대시보드 저장 없음(기본값)</li>"
        pol = "<li>탐지 정책 변경: 확인 실패</li>" if "F_POLICY_CHANGES" not in fx else ""
        return f"""
  <section aria-labelledby="s8h" id="s8">
    <div class="sec-head"><h2 id="s8h">8. 설정·정책 변경</h2></div>
    {self.lines(self.doc["commentary"]["S8"])}
    <ul class="facts"><li>로그인 실패 {_n(adm['login_fail'])}건</li>{gw}{pol}</ul>
    <div class="grid2">
      <div class="chart"><div class="chart-title"><h3>관리 작업</h3><span class="sub">로그인·로그아웃 제외</span></div>{self.table(["작업", "건수"], by)}</div>
      <div class="chart"><div class="chart-title"><h3>변경·기준 변경</h3></div>{self.table(["시각", "내용", "전→후"], crow, num_from=9, ids=[f"chg-{c}" for c in changes], cls="wrap")}</div>
    </div>
    <details class="table"><summary>최근 관리 작업 {len(recent)}건</summary>{self.table(["시각", "관리자", "작업", "대상", "결과"], recent, num_from=9)}</details>
  </section>"""

    # ---- 9. 운영 상태
    def s9(self) -> str:
        a, cur = self.a, self.a["cur"]
        d = a["decisions"]
        rows = [[_e(ag.RC_LABELS.get(rc, rc)), _n(n)] for rc, n in cur["unchecked_by_rc"].most_common()]
        tmo = " · ".join(f"{ag.ACTION_LABELS[k]} {v}" for k, v in cur["timeout_by_action"].items()) or "0건"
        only = [[_e(r["svc"]), _e(ag.CT_LABELS.get(r["ct"], r["ct"] or "기록 없음")), _n(r["n"])] for r in d["decision_only"]]
        st = self.meta.get("system")
        if st:
            inst = " · ".join(f"{_e(i['role'])} {_e(i['state'])}" for i in st.get("instances") or [])
            sys_txt = (f"검사 서버 {_e(st.get('detection') or '확인 실패')} · 조회 저장소 {'정상' if st.get('redis_ok') else '이상'} · "
                       f"판정 기록 전송 {'정상' if st.get('log_ok') else '이상'} · RDS {_e(st.get('rds') or '확인 실패')}"
                       + (f" · {inst}" if inst else ""))
        else:
            sys_txt = "확인 실패"
        pms = cur["pms"]
        prev = a["prev"] or {}
        has_prev = a["prev"] is not None
        b_pms = (pms["n"], prev["pms"]["n"] if has_prev else None)
        b_det = (d["rows"], prev["decisions"]["rows"] if has_prev and prev.get("decisions") else None)
        b_delay = (cur["delay"]["n"], prev["delay"]["n"] if has_prev else None)
        return f"""
  <section aria-labelledby="s9h" id="s9">
    <div class="sec-head"><h2 id="s9h">9. 운영 상태</h2></div>
    {self.lines(self.doc["commentary"]["S9"])}
    <div class="kpis">
      {self.kpi_time("F_P95", "Gateway 처리 시간 p95", _ms(pms['p95']), f"중앙 {_ms(pms['p50'])} · 최대 {_ms(pms['max'])} · {_n(pms['n'])}건", b_pms)}
      {self.kpi_time("F_DET_P95", "검사 서버 판정 시간 p95", _ms(d['p95']), f"중앙 {_ms(d['p50'])} · 호출 1회 기준", b_det)}
      {self.kpi_time("F_DELAY_P95", "이벤트 수신 지연 p95", _ms(cur['delay']['p95']), f"최대 {_ms(cur['delay']['max'])}", b_delay)}
      {self.kpi_time("F_STAGE_ERR", "탐지 단계 오류", _n(d['err_roots']), "요청 단위", self.bases())}
    </div>
    <ul class="facts">
      <li>처리 시간은 10/11 11:23(한국) 이후 기록만(그 전은 AI 서비스 응답 대기 포함으로 기준 다름)</li>
      <li>검사 시간 초과 처리: {_e(tmo)}</li>
      <li>판정만 있는 요청 {_n(d['decision_only_n'])}건(대시보드 기록 누락) · 이벤트만 있는 검사 대상 {_n(cur['event_only'])}건</li>
      <li>생성 시점 상태: {sys_txt}</li>
    </ul>
    <div class="grid2">
      <div class="chart"><div class="chart-title"><h3>검사 없이 통과 사유</h3></div>{self.table(["사유", "건수"], rows)}</div>
      <div class="chart"><div class="chart-title"><h3>판정만 있는 요청</h3></div>{self.table(["서비스", "경로", "요청"], only, num_from=2)}</div>
    </div>
  </section>"""

    # ---- 관측 범위 (설계 v3 A3) - 번호 없음, 9절 뒤
    def s_coverage(self) -> str:
        rows, ids = [], []
        for r in fr.coverage(self.a, self.fx):
            label = (f'<span class="subrow">└ {_e(r["label"])}</span>' if r["sub"] else f"<b>{_e(r['label'])}</b>")
            cur = f'<span class="na">{_e(r["cur"])}</span>' if r["cur"] == fr.NA else _e(r["cur"])
            prev = f'<span class="na">{_e(r["prev"])}</span>' if r["prev"] in (fr.NA, fr.NO_PREV) else _e(r["prev"])
            rows.append([label, cur, prev, _e(r["note"])])
            rid = "cov-" + (re.sub(r"[^a-z0-9_-]+", "-", r["key"].lower()).strip("-") or "x")
            ids.append(rid if rid not in ids else f"{rid}-{len(ids)}")
        comp = f"이전 {self.period_label('prev')}" if self.a["comparable"] else "이전 기간 기록 없음"
        return f"""
  <section aria-labelledby="covh" id="cov">
    <div class="sec-head"><h2 id="covh">관측 범위(못 본 것)</h2></div>
    <p class="note">이 보고서 숫자가 못 보는 부분 · 이번 {_e(self.period_label())} · {_e(comp)} · '확인 불가'는 이 보고서가 읽지 않는 자료</p>
    {self.table(["항목", "이번 기간", "이전 기간", "설명"], rows, num_from=9, ids=ids, cls="wrap cov")}
  </section>"""

    # ---- 10. 권고·다음 조치
    def s10(self) -> str:
        icon = SEV_ICON
        recs = {r["issue"]: r for r in self.doc["recs"]}
        cards = []
        for r in self.issues:
            rec = recs.get(r["code"])
            line = ""
            if rec:
                lt = rec["line"]
                line = f'<p class="rec">{_e(lt["text"])}</p>{self.link(rec["link"])}'
            cards.append(f"""
      <article class="rule {'off' if r['off'] else ''}" style="--sev:var(--st-{r['sev']})" id="iss-{r['code']}">
        <div class="stripe"></div>
        <div class="body">
          <div class="top"><span class="sev">{icon[r['sev']]}{_e(r['level'])}</span><h3>{_e(r['name'])}</h3></div>
          <p class="fact">{_e(r['fact'])}</p>
          {line}
        </div>
      </article>""")
        return f"""
  <section aria-labelledby="s10h" id="s10">
    <div class="sec-head"><h2 id="s10h">10. 권고·다음 조치</h2></div>
    <div class="rules">{''.join(cards)}</div>
    <p class="note">조치 링크는 대시보드 화면을 같은 탭에서 엶. '이 사용자 차단'은 차단 대화상자만 열고 저장은 관리자가 확인</p>
  </section>"""

    # ---- 11. 참고
    def s11(self) -> str:
        a = self.a
        notes = [
            "집계 단위: 대시보드 이벤트 1건(프롬프트 1건·파일 1건). 한국 시각 기준",
            f"시험 기록 제외: 확장 ID 접두어 {', '.join(ag.TEST_CLIENT_PREFIXES)} · 판정 기록은 서비스 {', '.join(ag.DECISION_SERVICES)}만",
            f"시연 문서 제외: 문서 번호가 {ag.DEMO_DOC_PREFIX}로 시작하는 문서만 일치한 이벤트와 그 문서(등록 문서 수에서도 뺌)",
            "파일 재전송(같은 사용자·서비스·파일·조치 4.348초 안)은 10/11 13:23(한국) 전 기록만 1건으로 묶음. 이후는 Gateway가 묶음",
            "질문 재시도(같은 사용자·서비스·조치·질문 본문 4.348초 안)는 기간 전체에서 1건으로 묶음(Gateway가 묶지 않음)",
            f"판정 기록 행 {_n(a['decisions']['rows'])}행(참고, 파일은 셀·문단마다 행)",
            "차단 건수는 유출 건수가 아님 · 사용자 등급은 보고용 참고값",
            "프로젝트 수준 보고서(실제 배포 아님)",
        ]
        for c in a["criteria"]:
            where = "기간 안" if c["inside"] else "비교 기간 안"
            notes.append(f"비교 주의: {ag.kst_hm(c['at'])} {c['label']}({where})")
        if self.meta.get("content_note"):
            notes.append(self.meta["content_note"])
        notes += list(self.meta.get("notes") or [])
        defs = "".join(f"<div><dt>{_e(t)}</dt><dd>{_e(d)}</dd></div>" for t, d in fr.definitions())
        return f"""
  <section aria-labelledby="s11h" id="s11">
    <div class="sec-head"><h2 id="s11h">11. 참고</h2></div>
    <ul class="limits">{''.join(f'<li>{_e(n)}</li>' for n in notes)}</ul>
    <div class="defs" id="defs"><h3>정의·기준</h3><dl>{defs}</dl></div>
  </section>"""

    def body(self) -> str:
        foot = f"""
  <footer>
    <span>자료: 대시보드 이벤트·판정 기록</span>
    <span>{_e(self.meta.get('stamp', ''))}</span>
  </footer>"""
        return (f'<div class="doc">{self.head()}{self.onepage()}{self.s1()}{self.s2()}{self.s3()}{self.s4()}{self.s5()}'
                f'{self.s_bypass()}{self.s6()}{self.s7()}{self.s8()}{self.s9()}{self.s_coverage()}{self.s10()}{self.s11()}'
                f'{foot}\n</div>')


def render(a: dict, fx: Facts, incidents: list[Incident], users: list[dict], issues: list[dict], doc: dict,
           meta: dict) -> str:
    ctx = Ctx(a, fx, incidents, users, issues, doc, meta)
    tpl = TEMPLATE.read_text(encoding="utf-8")
    title = f"PromptGate 보고서 {ag.md(a['start'])}–{ag.md(a['end'])}"
    return tpl.replace("{{TITLE}}", _e(title)).replace("{{BODY}}", ctx.body())
