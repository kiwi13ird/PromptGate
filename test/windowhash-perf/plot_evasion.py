"""회피 수법별 탐지율 그래프 — 무엇이 통하고 무엇이 안 통하는가."""
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
N = D["n_trials"]
res = D["result"]
rows = sorted(res.items(), key=lambda kv: (-kv[1]["hit"], -kv[1]["run"]))
names = [k for k, _ in rows]
vals = [100.0 * v["hit"] / N for _, v in rows]
runs = [v["run"] for _, v in rows]

GREEN, ORANGE, RED = "#16a34a", "#f59e0b", "#dc2626"


def color(v):
    return GREEN if v >= 90 else (ORANGE if v >= 30 else RED)


fig, ax = plt.subplots(figsize=(9.6, 6.2))
ypos = list(range(len(rows)))
ax.barh(ypos, vals, color=[color(v) for v in vals], height=0.64)
ax.set_yticks(ypos)
ax.set_yticklabels(names, fontsize=11)
ax.invert_yaxis()
ax.set_xlim(0, 132)
ax.set_xticks([0, 20, 40, 60, 80, 100])
ax.set_xticklabels(["0%", "20%", "40%", "60%", "80%", "100%"], fontsize=10)
ax.set_xlabel("차단한 비율", fontsize=11.5)
ax.grid(axis="x", alpha=0.25)
ax.set_axisbelow(True)
for s in ("top", "right", "left"):
    ax.spines[s].set_visible(False)

for i, (v, rn) in enumerate(zip(vals, runs)):
    ax.text(v + 1.5, i, f"{v:.0f}%", va="center", fontsize=10.5, color=color(v), fontweight="bold")
    ax.text(120, i, f"{rn:.0f}자", va="center", ha="right", fontsize=9.5, color="#64748b")
ax.text(120, -1.1, "원문이 이어지는\n평균 최대 길이", va="center", ha="right", fontsize=9, color="#64748b", linespacing=1.4)

ax.set_title("어떤 우회가 통하는가 — 회피 수법별 차단율", fontsize=15, pad=30, fontweight="bold")
ax.text(0.5, 1.055, f"기밀문서 20종 등록 · 600자 발췌를 수법별로 변형 · 각 {N}건 · 2026-09-19 실측",
        transform=ax.transAxes, ha="center", fontsize=10, color="#64748b")

fig.text(0.008, -0.14,
         "공백·기호·이모지를 넣거나 빼는 조작은 전처리에서 제거되므로 통하지 않는다. 문장을 섞거나 일부를 지우는 것도 남은 문장이 그대로면 잡힌다.\n"
         "반대로 글자를 30자보다 촘촘하게 고치면(오타·단어 치환·어절 섞기) 원문이 이어지는 구간이 30자 아래로 끊겨 탐지되지 않는다.\n"
         "오른쪽 회색 숫자는 변형 후에도 원문과 글자 그대로 이어지는 평균 최대 길이로, 이 값이 30자 아래로 내려가는 순간 차단율이 무너진다.",
         ha="left", fontsize=9.5, color="#475569", linespacing=1.7)
fig.savefig(OUT)
print("saved", OUT)
