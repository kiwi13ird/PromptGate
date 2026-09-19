"""한 장 요약: 입력 안에 원문이 끊기지 않고 이어지는 최대 길이 대비 차단율 (두 실험 동일 축)."""
import json, sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

rcParams["font.family"] = "Malgun Gothic"
rcParams["axes.unicode_minus"] = False
rcParams["figure.dpi"] = 180
rcParams["savefig.bbox"] = "tight"

R = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
OUT = Path(sys.argv[2])
samples = R["samples"]
W = R["window"]

BINS = [(0, 14), (15, 19), (20, 24), (25, 29), (30, 34), (35, 39), (40, 49), (50, 74), (75, 149), (150, 10 ** 9)]
LBL = ["~14", "15~19", "20~24", "25~29", "30~34", "35~39", "40~49", "50~74", "75~149", "150자~"]
SERIES = [("원문 일부만 복사", "#2563eb", "o"), ("복사 후 고쳐 쓰기", "#0f766e", "s")]

fig, ax = plt.subplots(figsize=(9.0, 5.2))
ax.axvspan(-0.5, 3.5, color="#fee2e2", alpha=0.7, zorder=0)
ax.axvline(3.5, color="#dc2626", ls="--", lw=1.3, zorder=1)

counts = {}
for name, color, marker in SERIES:
    xs, ys, ns = [], [], []
    for i, (lo, hi) in enumerate(BINS):
        sel = [s for s in samples if s[0] == name and lo <= s[1] <= hi]
        if len(sel) >= 10:
            xs.append(i)
            ys.append(100.0 * sum(1 for s in sel if s[2]) / len(sel))
            ns.append(len(sel))
    counts[name] = dict(zip(xs, ns))
    ax.plot(xs, ys, marker=marker, color=color, lw=2, ms=7, zorder=3, label=name)

ax.set_xticks(range(len(BINS)))
ax.set_xticklabels(LBL, fontsize=10)
ax.set_yticks([0, 20, 40, 60, 80, 100])
ax.set_yticklabels(["0%", "20%", "40%", "60%", "80%", "100%"], fontsize=10)
ax.set_ylim(-5, 110)
ax.set_xlim(-0.5, len(BINS) - 0.5)
ax.set_xlabel("입력 안에서 원문이 끊기지 않고 이어지는 최대 길이 (공백·기호 제외, 자)", fontsize=11.5)
ax.set_ylabel("차단한 비율", fontsize=11.5)
ax.grid(alpha=0.25, zorder=0)
ax.set_axisbelow(True)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)

ax.text(3.35, 55, "30자 미만으로 끊기면\n탐지 불가", color="#b91c1c", fontsize=10.5,
        ha="right", va="center", linespacing=1.5)
ax.annotate("기준선: 연속 30자", xy=(3.5, 105), xytext=(4.6, 88), fontsize=10, color="#dc2626",
            arrowprops=dict(arrowstyle="->", color="#dc2626", lw=1.2))
ax.legend(loc="center right", fontsize=11, frameon=True, framealpha=0.95, edgecolor="#e2e8f0")
ax.set_title("원문이 30자만 이어지면 방식과 무관하게 차단된다", fontsize=15, pad=26, fontweight="bold")
ax.text(0.5, 1.045, "기밀문서 20종 등록 · 입력 1,320건을 '이어지는 최대 길이'로 묶어 집계 · 2026-09-19 실측",
        transform=ax.transAxes, ha="center", fontsize=10, color="#64748b")

fig.text(0.008, -0.30,
         "두 계열은 만드는 방법만 다르다. 파란색은 원문을 그만큼만 복사한 입력, 초록색은 600~2,000자를 복사한 뒤 군데군데 고쳐 써서\n"
         "원문이 그만큼만 이어지게 만든 입력이다. 묶고 나면 두 곡선이 겹친다 — 어떻게 만들었는지가 아니라 원문이 얼마나 이어지는지가 결정한다.\n"
         "무관한 문서를 잘못 차단한 경우 472건 중 0건 · 판정 시간 300자 0.004초, 문서 전체(5.3만자) 0.09초\n"
         "※ 자기 말로 다시 쓰거나 요약·번역한 입력은 이어지는 구간이 없어 구조상 탐지되지 않음(이번 측정 대상 아님).",
         ha="left", fontsize=9.5, color="#475569", linespacing=1.7)
fig.savefig(OUT)
print("saved", OUT)
for name in counts:
    print(name, counts[name])
