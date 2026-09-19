"""회피 수법별 탐지율 — 어떤 우회가 통하고 어떤 우회가 통하지 않는가."""
import json, random, re, sys
from difflib import SequenceMatcher
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
LQ = 600


def cstr(s):
    return "".join(chr(c) for c in compact(normalize_text(s)).codes)


def sents(t):
    return [s for s in re.split(r"(?<=[.!?])\s+|\n+", t) if s.strip()]


def typo(t, g, p):
    ch = list(t)
    idx = [i for i, c in enumerate(ch) if not c.isspace()]
    for i in g.sample(idx, max(1, int(len(idx) * p))):
        ch[i] = g.choice(SYL)
    return "".join(ch)


def drop_chars(t, g, p):
    ch = list(t)
    idx = [i for i, c in enumerate(ch) if not c.isspace()]
    for i in sorted(g.sample(idx, max(1, int(len(idx) * p))), reverse=True):
        del ch[i]
    return "".join(ch)


JOSA = [("은", "는"), ("는", "은"), ("이", "가"), ("가", "이"), ("을", "를"), ("를", "을"), ("에서", "에"), ("으로", "로")]


def swap_josa(t, g):
    out = []
    for w in t.split(" "):
        for a, b in JOSA:
            if len(w) > 2 and w.endswith(a):
                w = w[: -len(a)] + b
                break
        out.append(w)
    return " ".join(out)


def shuffle_words(t, g):
    return " ".join(" ".join(g.sample(s.split(" "), len(s.split(" ")))) for s in sents(t))


def cut_head(t, g):
    out = []
    for s in sents(t):
        w = s.split(" ")
        out.append(" ".join(w[2:]) if len(w) > 4 else s)
    return " ".join(out)


def every_n_word(t, gap, g):
    words, out, run = t.split(" "), [], 0
    for w in words:
        if run >= gap and w.strip():
            out.append("".join(g.choice(SYL) for _ in range(max(1, len(w)))))
            run = 0
        else:
            out.append(w)
            run += len(w) + 1
    return " ".join(out)


EVASIONS = [
    ("그대로 복사", lambda t, g: t),
    ("띄어쓰기 전부 제거", lambda t, g: t.replace(" ", "")),
    ("단어 사이에 기호 삽입", lambda t, g: "·".join(t.split(" "))),
    ("문장마다 이모지 삽입", lambda t, g: " ".join(s + " :)" for s in sents(t))),
    ("문장 순서 섞기", lambda t, g: " ".join(g.sample(sents(t), len(sents(t))))),
    ("조사만 전부 바꾸기", lambda t, g: swap_josa(t, g)),
    ("문장 앞 두 어절씩 삭제", lambda t, g: cut_head(t, g)),
    ("40자마다 단어 치환", lambda t, g: every_n_word(t, 40, g)),
    ("20자마다 단어 치환", lambda t, g: every_n_word(t, 20, g)),
    ("10자마다 단어 치환", lambda t, g: every_n_word(t, 10, g)),
    ("글자 3% 오타", lambda t, g: typo(t, g, 0.03)),
    ("글자 5% 오타", lambda t, g: typo(t, g, 0.05)),
    ("글자 10% 오타", lambda t, g: typo(t, g, 0.10)),
    ("글자 5% 삭제", lambda t, g: drop_chars(t, g, 0.05)),
    ("문장 안 어절 순서 섞기", lambda t, g: shuffle_words(t, g)),
]

res = {}
for name, fn in EVASIONS:
    g = random.Random(5)
    ok, runs = 0, []
    for _ in range(N):
        while True:
            d = g.choice(PROSE)
            tx = docs[d]
            if len(tx) > LQ + 1:
                break
        st = g.randrange(0, len(tx) - LQ)
        src = tx[st:st + LQ]
        q = fn(src, g)
        x = decide(query_text(r, q))
        ok += bool(x.blocked and x.signal and x.signal.x_evidence == d)
        a, b = cstr(src), cstr(q)
        runs.append(SequenceMatcher(None, a, b, autojunk=False).find_longest_match(0, len(a), 0, len(b)).size)
    res[name] = {"hit": ok, "n": N, "run": sum(runs) / len(runs)}
    print(f"{name}: {ok}/{N}, 평균 최대 연속 {res[name]['run']:.0f}자", flush=True)

Path(sys.argv[1]).write_text(json.dumps({"n_trials": N, "excerpt": LQ, "result": res}, ensure_ascii=False, indent=1), encoding="utf-8")
print("saved")
