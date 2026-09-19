"""입력별로 '원문이 끊기지 않고 이어지는 최대 길이'(압축 기준)를 실제로 재고, 그 값에 대한 차단율을 구한다."""
import json, random, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # 저장소 루트
sys.path.insert(0, str(ROOT / "detection"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakeredis
from windowhash import store
from windowhash.detect import decide, query_text
from windowhash.ingest import ingest_directory
from windowhash.hashing import compact
from preprocessing.router import process_input
from preprocessing.normalizer import normalize_text

sys.stdout.reconfigure(encoding="utf-8")
TESTBED = ROOT / "test" / "testbed" / "generated"
r = fakeredis.FakeRedis(decode_responses=True)
conn = store.connect(":memory:")
ingest_directory(conn, r, TESTBED)
docs = {p.stem: process_input(str(p)).normalized_text for p in sorted(TESTBED.iterdir()) if p.suffix.lower() in (".docx", ".xlsx")}
TABLE = ["06_급여대장", "12_고객사리스트", "14_영업파이프라인", "17_접근권한매트릭스", "19_VIP문의이력"]
PROSE = [d for d in docs if d not in TABLE]
SYL = [chr(c) for c in range(0xAC00, 0xAC00 + 600)]
N = 30


def clen(s):
    return len(compact(normalize_text(s)).codes)


def hit(q, d):
    x = decide(query_text(r, q))
    return bool(x.blocked and x.signal and x.signal.x_evidence == d)


def edit_every(text, gap, g):
    """gap자마다 단어 하나를 바꾸고, 손대지 않고 남은 구간들을 함께 돌려준다."""
    words = text.split(" ")
    out, kept, cur, run = [], [], [], 0
    for w in words:
        if run >= gap and w.strip():
            out.append("".join(g.choice(SYL) for _ in range(max(1, len(w)))))
            kept.append(" ".join(cur))
            cur, run = [], 0
        else:
            out.append(w)
            cur.append(w)
            run += len(w) + 1
    kept.append(" ".join(cur))
    return " ".join(out), max(clen(s) for s in kept)


samples = []  # (계열, 원문이 이어지는 최대 길이(압축), 차단 여부)

# 계열 1 — 원문 일부만 복사 (입력 전체가 이어지는 구간)
g = random.Random(42)
for Lq in (20, 25, 30, 32, 35, 38, 40, 45, 50, 60, 75, 100, 150, 300, 600, 2000):
    for _ in range(N):
        while True:
            d = g.choice(list(docs))
            tx = docs[d]
            if len(tx) > Lq + 1:
                break
        st = g.randrange(0, len(tx) - Lq)
        q = tx[st:st + Lq]
        samples.append(("원문 일부만 복사", clen(q), hit(q, d)))
    print("발췌", Lq, "완료", flush=True)

# 계열 2 — 복사 후 고쳐 쓰기 (남은 구간 중 가장 긴 것)
for Lq in (600, 2000):
    g = random.Random(11)
    for gap in (8, 10, 12, 15, 18, 20, 25, 30, 35, 40, 50, 75, 100, 150):
        for _ in range(N):
            while True:
                d = g.choice(PROSE)
                tx = docs[d]
                if len(tx) > Lq + 1:
                    break
            st = g.randrange(0, len(tx) - Lq)
            q, run = edit_every(tx[st:st + Lq], gap, g)
            samples.append(("복사 후 고쳐 쓰기", run, hit(q, d)))
        print("편집", Lq, gap, "완료", flush=True)

Path(sys.argv[1]).write_text(json.dumps({"window": 30, "samples": samples}, ensure_ascii=False), encoding="utf-8")
# 요약 출력
BINS = [(0, 14), (15, 19), (20, 24), (25, 29), (30, 34), (35, 39), (40, 49), (50, 74), (75, 149), (150, 10 ** 9)]
for series in ("원문 일부만 복사", "복사 후 고쳐 쓰기"):
    print(f"\n[{series}]")
    for lo, hi in BINS:
        sel = [s for s in samples if s[0] == series and lo <= s[1] <= hi]
        if sel:
            print(f"  {lo}~{hi}: {sum(1 for s in sel if s[2])}/{len(sel)}")
