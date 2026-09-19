"""한 장 요약: 원문이 이어지는 길이 구간별 차단율."""
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

D = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
OUT = Path(sys.argv[2])
S = D["samples"]

BINS = [((0, 19), "10~19자"), ((20, 29), "20~29자"), ((30, 39), "30~39자"),
        ((40, 59), "40~59자"), ((60, 99), "60~99자"), ((100, 10 ** 9), "100자 이상")]
GREEN, RED = "#16a34a", "#dc2626"

labels, vals, ns = [], [], []
for (lo, hi), name in BINS:
    sel = [s for s in S if lo <= s[1] <= hi]
    labels.append(name)
    vals.append(100.0 * sum(1 for s in sel if s[2]) / len(sel))
    ns.append(len(sel))

fig, ax = plt.subplots(figsize=(8.6, 4.6))
colors = [RED if v < 50 else GREEN for v in vals]
ax.bar(labels, vals, color=colors, width=0.62)
ax.set_xticks(range(len(labels)))
ax.set_xticklabels([a + "\n(" + str(b) + "건)" for a, b in zip(labels, ns)])
ax.axvline(1.5, color="#94a3b8", ls="--", lw=1.2)
ax.text(1.42, 112, "이 아래로 끊기면 탐지 불가", ha="right", fontsize=11.5, color=RED)
ax.text(1.62, 112, "이만큼 이어지면 전부 차단", ha="left", fontsize=11.5, color="#166534")

ax.set_ylim(0, 126)
ax.set_yticks([0, 20, 40, 60, 80, 100])
ax.set_yticklabels(["0%", "20%", "40%", "60%", "80%", "100%"], fontsize=10.5)
ax.set_ylabel("차단한 비율", fontsize=12)
ax.set_xlabel("입력 안에서 원문이 끊기지 않고 이어지는 길이 (공백·기호 제외)", fontsize=12)
ax.tick_params(axis="x", labelsize=11.5)
ax.grid(axis="y", alpha=0.25)
ax.set_axisbelow(True)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
for i, (v, n) in enumerate(zip(vals, ns)):
    ax.text(i, v + 3, f"{v:.0f}%", ha="center", fontsize=12, color=colors[i], fontweight="bold")

ax.set_title("원문이 30자만 이어지면 차단된다", fontsize=16, pad=28, fontweight="bold")
ax.text(0.5, 1.065, "기밀문서 20종 등록 · 붙여넣기·발췌·고쳐쓰기 입력 1,320건 · 2026-09-19 실측",
        transform=ax.transAxes, ha="center", fontsize=10.5, color="#64748b")
fig.text(0.02, -0.10,
         "무관한 문서를 잘못 차단한 경우 472건 중 0건 · 판정 시간 300자 0.004초, 문서 전체(5.3만자) 0.09초",
         ha="left", fontsize=10, color="#475569")
fig.savefig(OUT)
print("saved", OUT, list(zip(labels, [round(v) for v in vals], ns)))
