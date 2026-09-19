"""짧은 발췌 길이 구간(20~100자)까지 포함한 원문 탐지율 — 하한 확인."""
import json, random, sys
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
r = fakeredis.FakeRedis(decode_responses=True)
conn = store.connect(":memory:")
ingest_directory(conn, r, TESTBED)
docs = {p.stem: process_input(str(p)).normalized_text for p in sorted(TESTBED.iterdir()) if p.suffix.lower() in (".docx", ".xlsx")}
TABLE = ["06_급여대장", "12_고객사리스트", "14_영업파이프라인", "17_접근권한매트릭스", "19_VIP문의이력"]
PROSE = [d for d in docs if d not in TABLE]
N = 30
LENS = [20, 25, 30, 35, 40, 50, 60, 75, 100, 150, 300, 600, 1000, 2000]


def hit(q, d):
    x = decide(query_text(r, q))
    return bool(x.blocked and x.signal and x.signal.x_evidence == d)


res = {}
for label, group in (("산문", PROSE), ("표", TABLE)):
    g = random.Random(42)
    row = {}
    for Lq in LENS:
        ok = 0
        for _ in range(N):
            while True:
                d = g.choice(group)
                tx = docs[d]
                if len(tx) > Lq + 1:
                    break
            st = g.randrange(0, len(tx) - Lq)
            ok += hit(tx[st:st + Lq], d)
        row[Lq] = ok
        print(label, Lq, ok, flush=True)
    res[label] = row
Path(sys.argv[1]).write_text(json.dumps({"n_trials": N, "lens": LENS, "result": res}, ensure_ascii=False, indent=1), encoding="utf-8")
print("saved")
