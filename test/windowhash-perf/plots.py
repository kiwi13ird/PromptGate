"""wh_eval.json → 보고서용 그래프(PNG)."""
import json, sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import rcParams

rcParams["font.family"] = "Malgun Gothic"
rcParams["axes.unicode_minus"] = False
rcParams["figure.dpi"] = 160
rcParams["savefig.bbox"] = "tight"

D = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
N = D["n_trials"]
BLUE, GRAY, RED = "#2563eb", "#94a3b8", "#dc2626"


def pct(v):
    return 100.0 * v / N


# 1. 원문 발췌 길이별 탐지율 (짧은 구간 포함)
S = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
fig, ax = plt.subplots(figsize=(6.8, 3.6))
lens = S["lens"]
for label, color, marker in (("산문", BLUE, "o"), ("표", "#0f766e", "s")):
    ys = [100.0 * S["result"][label][str(L)] / S["n_trials"] for L in lens]
    ax.plot(range(len(lens)), ys, marker=marker, color=color, label=f"{label} 문서")
ax.axvline(lens.index(40), color=GRAY, ls="--", lw=1)
ax.text(lens.index(40) + 0.1, 50, "창 30자 = 원문 약 40자", color="#475569", fontsize=8)
ax.set_xticks(range(len(lens)))
ax.set_xticklabels([f"{L:,}" for L in lens], fontsize=8)
ax.set_ylim(0, 105)
ax.set_ylabel("탐지율 (%)")
ax.set_xlabel("발췌 길이")
ax.set_title(f"원문 그대로 발췌한 입력의 탐지율 (각 {N}건)")
ax.grid(axis="y", alpha=0.3)
ax.legend(loc="lower right")
fig.savefig(OUT / "01_발췌길이별_탐지율.png")
plt.close(fig)

# 2. 문장 편집 유형별 탐지율
fig, ax = plt.subplots(figsize=(7.2, 5.2))
names = list(D["edits"]["600"].keys())
y = range(len(names))
h = 0.38
v600 = [pct(D["edits"]["600"][n]) for n in names]
v1000 = [pct(D["edits"]["1000"][n]) for n in names]
ax.barh([i + h / 2 for i in y], v600, height=h, color=BLUE, label="600자 발췌")
ax.barh([i - h / 2 for i in y], v1000, height=h, color="#93c5fd", label="1,000자 발췌")
ax.set_yticks(list(y))
ax.set_yticklabels(names)
ax.invert_yaxis()
ax.set_xlim(0, 108)
ax.set_xlabel("탐지율 (%)")
ax.set_title(f"발췌 후 편집한 입력의 탐지율 (각 {N}건)")
ax.grid(axis="x", alpha=0.3)
ax.legend(loc="lower left", bbox_to_anchor=(0.0, -0.22), ncol=2, frameon=False)
for i, (a, b) in enumerate(zip(v600, v1000)):
    ax.text(a + 1, i + h / 2, f"{a:.0f}", va="center", fontsize=7)
    ax.text(b + 1, i - h / 2, f"{b:.0f}", va="center", fontsize=7)
fig.savefig(OUT / "02_편집유형별_탐지율.png")
plt.close(fig)

# 3. 표 복사 방식별 탐지율
fig, ax = plt.subplots(figsize=(6.4, 3.2))
names = list(D["table_copy"].keys())
vals = [pct(D["table_copy"][n]) for n in names]
colors = [BLUE if v >= 50 else RED for v in vals]
ax.bar(names, vals, color=colors)
ax.set_ylim(0, 108)
ax.set_ylabel("탐지율 (%)")
ax.set_title(f"급여대장 3행을 서로 다른 방식으로 복사 (각 {N}건)")
ax.grid(axis="y", alpha=0.3)
plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
for i, v in enumerate(vals):
    ax.text(i, v + 2, f"{v:.0f}%", ha="center", fontsize=8)
fig.savefig(OUT / "03_표복사_방식별_탐지율.png")
plt.close(fig)

# 4. 오탐
fig, ax = plt.subplots(figsize=(6.0, 3.0))
names = list(D["false_positive"].keys())
hits = [D["false_positive"][n][0] for n in names]
tot = [D["false_positive"][n][1] for n in names]
ax.bar(names, tot, color="#e2e8f0", label="검사 건수")
ax.bar(names, hits, color=RED, label="오탐(차단) 건수")
ax.set_ylabel("건수")
ax.set_title("기밀문서와 무관한 입력의 오탐")
ax.grid(axis="y", alpha=0.3)
ax.legend()
for i, (hv, tv) in enumerate(zip(hits, tot)):
    ax.text(i, tv + max(tot) * 0.02, f"{hv}/{tv}", ha="center", fontsize=9)
plt.setp(ax.get_xticklabels(), rotation=12, ha="right")
fig.savefig(OUT / "04_오탐.png")
plt.close(fig)

# 5. 지연
fig, ax = plt.subplots(figsize=(6.4, 3.2))
names = list(D["latency_ms"].keys())
vals = [D["latency_ms"][n] for n in names]
ax.bar(names, vals, color=BLUE)
ax.axhline(500, color=RED, ls="--", lw=1)
ax.text(len(names) - 0.4, 520, "Gateway 제한 500ms", color=RED, ha="right", fontsize=8)
ax.set_ylabel("판정 소요 시간 (ms)")
ax.set_title("입력 길이별 판정 지연")
ax.grid(axis="y", alpha=0.3)
plt.setp(ax.get_xticklabels(), rotation=18, ha="right")
for i, v in enumerate(vals):
    ax.text(i, v + max(vals) * 0.03, f"{v:.0f}", ha="center", fontsize=8)
fig.savefig(OUT / "05_지연.png")
plt.close(fig)

# 6. 문서별 색인 규모
fig, ax = plt.subplots(figsize=(7.2, 4.4))
items = sorted(D["doc_sizes"].items(), key=lambda kv: kv[1]["windows"], reverse=True)
names = [k for k, _ in items]
vals = [v["windows"] for _, v in items]
ax.barh(names, vals, color=BLUE)
ax.invert_yaxis()
ax.set_xlabel("창(30자) 개수")
ax.set_title(f"문서별 색인 규모 (합계 {sum(vals):,}개)")
ax.grid(axis="x", alpha=0.3)
for i, v in enumerate(vals):
    ax.text(v + max(vals) * 0.01, i, f"{v:,}", va="center", fontsize=7)
fig.savefig(OUT / "06_문서별_색인규모.png")
plt.close(fig)

# 7. 편집 간격별 탐지율
G = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
fig, ax = plt.subplots(figsize=(6.8, 3.6))
gaps = G["gaps"]
for Lq, color, marker in (("600", BLUE, "o"), ("2000", "#0f766e", "s")):
    ys = [100.0 * G["result"][Lq][str(g)] / G["n_trials"] for g in gaps]
    ax.plot(gaps, ys, marker=marker, color=color, label=f"{int(Lq):,}자 발췌")
ax.axvline(30, color=RED, ls="--", lw=1)
ax.text(31, 8, "창 길이 30자", color=RED, fontsize=8)
ax.set_xlabel("편집 간격 (원문이 연속으로 남는 길이, 자)")
ax.set_ylabel("탐지율 (%)")
ax.set_ylim(-3, 105)
ax.set_title(f"몇 자마다 고쳐 쓰면 탐지를 벗어나는가 (각 {G['n_trials']}건)")
ax.grid(alpha=0.3)
ax.legend(loc="lower right")
fig.savefig(OUT / "07_편집간격별_탐지율.png")
plt.close(fig)

print("saved to", OUT)
