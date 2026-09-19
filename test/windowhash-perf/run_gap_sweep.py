"""편집 간격(원문이 연속으로 남는 길이)에 따른 탐지율 곡선 — 창 30자 한계의 실측."""
import json, random, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # 저장소 루트
sys.path.insert(0, str(ROOT / "detection"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakeredis
from windowhash import store
from windowhash.detect import decide, query_text
from windowhash.ingest import ingest_directory
from preprocessing.router import process_input

sys.stdout.reconfigure(encoding="utf-8")
TESTBED = ROOT / "test" / "testbed" / "generated"
OUT = Path(sys.argv[1])

r = fakeredis.FakeRedis(decode_responses=True)
conn = store.connect(":memory:")
ingest_directory(conn, r, TESTBED)
docs = {p.stem: process_input(str(p)).normalized_text for p in sorted(TESTBED.iterdir()) if p.suffix.lower() in (".docx", ".xlsx")}
TABLE = ["06_급여대장", "12_고객사리스트", "14_영업파이프라인", "17_접근권한매트릭스", "19_VIP문의이력"]
PROSE = [d for d in docs if d not in TABLE]
SYL = [chr(c) for c in range(0xAC00, 0xAC00 + 600)]
N = 30


def edit_every(text, gap, g):
    """대략 gap자마다 단어 하나를 무작위 글자로 바꾼다."""
    words = text.split(" ")
    out, run = [], 0
    for w in words:
        if run >= gap and w.strip():
            out.append("".join(g.choice(SYL) for _ in range(max(1, len(w)))))
            run = 0
        else:
            out.append(w)
            run += len(w) + 1
    return " ".join(out)


def hit(q, d):
    x = decide(query_text(r, q))
    return bool(x.blocked and x.signal and x.signal.x_evidence == d)


GAPS = [10, 15, 20, 25, 30, 35, 40, 50, 75, 100, 150]
res = {}
for Lq in (600, 2000):
    row = {}
    for gap in GAPS:
        g = random.Random(7)
        ok = 0
        for _ in range(N):
            while True:
                d = g.choice(PROSE)
                tx = docs[d]
                if len(tx) > Lq + 1:
                    break
            st = g.randrange(0, len(tx) - Lq)
            ok += hit(edit_every(tx[st:st + Lq], gap, g), d)
        row[gap] = ok
        print(Lq, gap, ok, flush=True)
    res[Lq] = row
Path(OUT).write_text(json.dumps({"n_trials": N, "gaps": GAPS, "result": res}, ensure_ascii=False, indent=1), encoding="utf-8")
print("saved", OUT)
