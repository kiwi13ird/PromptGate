"""windowhash_eval.py와 같은 실험을 돌리되 결과를 JSON으로 저장한다(그래프용)."""
import json, os, random, re, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # 저장소 루트
sys.path.insert(0, str(ROOT / "detection"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakeredis
from windowhash import store
from windowhash.detect import decide, query_text
from windowhash.ingest import ingest_directory
from preprocessing.router import process_input
from preprocessing.normalizer import normalize_text
from fp_tables_gen import pay_row, cus_row, rng as frng

sys.stdout.reconfigure(encoding="utf-8")
TESTBED = ROOT / "test" / "testbed" / "generated"
OUT = Path(sys.argv[1])

r = fakeredis.FakeRedis(decode_responses=True)
conn = store.connect(":memory:")
t = time.perf_counter()
ingest_directory(conn, r, TESTBED)
ing = (time.perf_counter() - t) * 1000
docs = {p.stem: process_input(str(p)).normalized_text for p in sorted(TESTBED.iterdir()) if p.suffix.lower() in (".docx", ".xlsx")}
TABLE = ["06_급여대장", "12_고객사리스트", "14_영업파이프라인", "17_접근권한매트릭스", "19_VIP문의이력"]
PROSE = [d for d in docs if d not in TABLE]
RES = {"ingest_ms": ing, "windows": store.window_count(conn), "redis_keys": r.dbsize(), "n_trials": 30}


def hit(q, d):
    x = decide(query_text(r, q))
    return bool(x.blocked and x.signal and x.signal.x_evidence == d)


N = 30
RES["verbatim"] = {}
for label, group in (("산문", PROSE), ("표", TABLE)):
    g = random.Random(42)
    row = {}
    for Lq in (100, 150, 300, 600, 1000, 2000):
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
    RES["verbatim"][label] = row
    print(label, row, flush=True)


def sents(t):
    return [s for s in re.split(r"(?<=[.!?])\s+|\n+", t) if s.strip()]


SYL = [chr(c) for c in range(0xAC00, 0xAC00 + 600)]
FILL = ["이 부분은 내부 검토 후 다시 정리할 예정입니다.", "관련 내용은 별도 회의에서 논의하기로 하였다.", "세부 일정은 담당 부서와 협의하여 확정한다."]


def sub_words(s, k, g):
    w = s.split(" ")
    for j in g.sample(range(len(w)), min(k, len(w))):
        w[j] = "".join(g.choice(SYL) for _ in range(max(1, len(w[j]))))
    return " ".join(w)


def polite(t):
    for a, b in (("한다.", "합니다."), ("된다.", "됩니다."), ("있다.", "있습니다."), ("없다.", "없습니다."), ("이다.", "입니다.")):
        t = t.replace(a, b)
    return t


EDITS = [("원문 그대로", lambda t, g: t),
         ("문장 1개 삭제", lambda t, g: " ".join(s for i, s in enumerate(sents(t)) if i != g.randrange(len(sents(t))))),
         ("문장 1개 교체", lambda t, g: " ".join(g.choice(FILL) if i == g.randrange(len(sents(t))) else s for i, s in enumerate(sents(t)))),
         ("문장 1개 삽입", lambda t, g: " ".join(sents(t)[:3] + [g.choice(FILL)] + sents(t)[3:])),
         ("프롬프트로 감싸기", lambda t, g: "다음 문서를 요약해줘:\n" + t + "\n핵심만 3줄로."),
         ("존댓말 변환", lambda t, g: polite(t)),
         ("숫자 전부 변경", lambda t, g: re.sub(r"\d", lambda m: str((int(m.group()) + g.randint(1, 9)) % 10), t)),
         ("문장 순서 섞기", lambda t, g: " ".join(g.sample(sents(t), len(sents(t))))),
         ("불릿 형식", lambda t, g: "\n".join("- " + s for s in sents(t))),
         ("문장 절반만", lambda t, g: " ".join(sents(t)[::2])),
         ("모든 문장 단어 1개 치환", lambda t, g: " ".join(sub_words(s, 1, g) for s in sents(t))),
         ("모든 문장 단어 2개 치환", lambda t, g: " ".join(sub_words(s, 2, g) for s in sents(t))),
         ("5단어마다 치환", lambda t, g: sub_words(t, len(t.split(" ")) // 5, g))]
RES["edits"] = {}
for Lq in (600, 1000):
    g = random.Random(11)
    row = {}
    for name, fn in EDITS:
        ok = 0
        for _ in range(N):
            while True:
                d = g.choice(PROSE)
                tx = docs[d]
                if len(tx) > Lq + 1:
                    break
            st = g.randrange(0, len(tx) - Lq)
            ok += hit(fn(tx[st:st + Lq], g), d)
        row[name] = ok
    RES["edits"][Lq] = row
    print(Lq, row, flush=True)

rows = [l for l in docs["06_급여대장"].split("\n") if l.count("|") >= 2][1:]
g = random.Random(3)
det = {}
for name, f in (("문서에서 그대로", lambda b: "\n".join(b)),
                ("엑셀 복사(탭)", lambda b: "\n".join(x.replace(" | ", "\t") for x in b)),
                ("메모장(공백)", lambda b: "\n".join(x.replace(" | ", " ") for x in b)),
                ("셀마다 줄바꿈", lambda b: "\n".join(x.replace(" | ", "\n") for x in b)),
                ("1행만", lambda b: b[0]),
                ("숫자 전부 변경", lambda b: re.sub(r"\d", lambda m: str((int(m.group()) + 3) % 10), "\n".join(b)))):
    ok = 0
    for _ in range(N):
        st = g.randrange(0, len(rows) - 3)
        ok += hit(f(rows[st:st + 3]), "06_급여대장")
    det[name] = ok
RES["table_copy"] = det
print(det, flush=True)

neg = []
NEG_DIR = Path(os.environ.get("NEG_CORPUS", ROOT / "docs"))  # 무관 문서 코퍼스(없으면 0건)
for p in NEG_DIR.rglob("*.md"):
    if "testbed-dataset" in str(p):
        continue
    tx = re.sub(r"```.*?```", " ", normalize_text(p.read_text(encoding="utf-8", errors="ignore")), flags=re.S)
    for i in range(0, len(tx) - 600, 600):
        neg.append(tx[i:i + 600])
frng.seed(11)
fpn = sum(decide(query_text(r, q)).blocked for q in neg)
fpp = sum(decide(query_text(r, "\n".join(pay_row(i) for i in range(frng.randint(4, 25))))).blocked for _ in range(60))
fpc = sum(decide(query_text(r, "\n".join(cus_row(i) for i in range(frng.randint(4, 25))))).blocked for _ in range(60))
RES["false_positive"] = {"무관 업무 산문 600자": [fpn, len(neg)], "가짜 급여대장": [fpp, 60], "가짜 고객사리스트": [fpc, 60]}
print(RES["false_positive"], flush=True)

miss = [d for d, tx in docs.items() if not hit(tx, d)]
RES["full_doc_miss"] = miss
g = random.Random(1)
words = "회의 일정 조정 부탁드립니다 다음주 화요일 오전 열시 가능 여부 확인 후 회신 바랍니다 프로젝트 진행 상황 공유 자료 검토 의견 반영 예정 감사합니다".split()


def unrelated(n):
    s = ""
    while len(s) < n:
        s += g.choice(words) + " "
    return s[:n]


lat = {}
for label, q in (("300자 발췌", docs["15_NDA_초안"][216:516]), ("2,000자 발췌", docs["01_사업전략_방향_보고서"][1000:3000]),
                 ("문서 전체(5.3만자)", docs["09_아키텍처_설계서"]), ("무관 600자", unrelated(600)),
                 ("무관 5,000자", unrelated(5000)), ("무관 20,000자", unrelated(20000))):
    best = min((time.perf_counter(), decide(query_text(r, q)), time.perf_counter())[::2] for _ in range(3))
    t0 = time.perf_counter()
    decide(query_text(r, q))
    lat[label] = (time.perf_counter() - t0) * 1000
RES["latency_ms"] = lat
from windowhash import engine  # noqa: E402
RES["doc_sizes"] = {d: {"chars": len(tx), "windows": len(engine.document_windows(tx))} for d, tx in docs.items()}
print(lat, flush=True)
OUT.write_text(json.dumps(RES, ensure_ascii=False, indent=1), encoding="utf-8")
print("saved", OUT)
