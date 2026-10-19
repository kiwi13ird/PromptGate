"""1단계: 추가 실험 없이 기존 판정(base-v1)에 두 가지 거르기를 적용해 다시 채점한다 — 로컬 실행.

F1 근거 검증 강화: 'ok'인 포함 판정 중, 모델이 낸 원문 인용(doc_quote)과 입력 인용(input_quote)이
    같은 구체적 값을 하나 이상 공유할 때만 통과.
    같은 값 = 숫자(쉼표 제거, 2자리 이상) 또는 식별 조각(공백·기호 뺀 3글자 조각 중 테스트베드 20종에서
    2개 이하 문서에만 나오는 것, 창 해시 식별력 규칙과 같은 원리).
F2 호출 전 거르기: 입력과 후보 원문(3개 중 어느 것이든) 사이에 식별 조각이 하나도 겹치지 않으면
    LLM을 부르지 않고 '포함 아님'.

    python recompute_filters.py --db results/judge_base-v1.sqlite3 --eval eval_v1.jsonl --run-id base-v1
"""
import argparse
import json
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

P_TYPES = ("P1", "P2", "P3", "P4", "P5")
N_TYPES = ("N1", "N2", "N3", "N4")
NAMES = {"P1": "재작성", "P2": "요약", "P3": "영어 번역", "P4": "구어체", "P5": "형식 변환",
         "N1": "같은 주제", "N2": "비슷하지만 다른 사실", "N3": "후보 잘못 짝지음", "N4": "무관 프롬프트"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--eval", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", default="results/recompute_base-v1.json")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    from preprocessing.normalizer import normalize_text
    from preprocessing.router import process_input
    from windowhash.hashing import compact

    def cstr(s):
        return "".join(chr(c) for c in compact(normalize_text(s or "")).codes)

    gen = ROOT / "docs" / "testbed-dataset" / "generated"
    df = defaultdict(int)
    for p in sorted(gen.iterdir()):
        if p.suffix.lower() in (".docx", ".xlsx"):
            c = cstr(process_input(str(p)).normalized_text)
            for g in {c[i:i + 3] for i in range(len(c) - 2)}:
                df[g] += 1

    def ident(s):
        c = cstr(s)
        return {c[i:i + 3] for i in range(len(c) - 2) if 0 < df.get(c[i:i + 3], 0) <= 2}

    def nums(s):
        return {m.replace(",", "") for m in re.findall(r"\d[\d,]*\d", s or "")}

    items = {json.loads(x)["item_id"]: json.loads(x)
             for x in Path(a.eval).read_text(encoding="utf-8").splitlines() if x.strip()}
    db = sqlite3.connect(a.db)
    db.row_factory = sqlite3.Row
    rows = {r["decision_id"]: dict(r) for r in db.execute("SELECT * FROM judgments WHERE run_id=?", (a.run_id,))}

    preds = {"기존 (근거 검증 통과)": {}, "+F1 근거 검증 강화": {}, "+F2 호출 전 거르기": {}, "+F1+F2": {}}
    f2_skip = {}
    for iid, it in items.items():
        r = rows[iid]
        base = r["status"] == "ok" and r["contains"] == 1
        f1 = False
        if base:
            o = json.loads(r["raw_output"])
            dq, iq = o.get("doc_quote") or "", o.get("input_quote") or ""
            f1 = bool((nums(dq) & nums(iq)) or (ident(dq) & ident(iq)))
        inp = ident(it["input_text"])
        skip = not any(inp & ident(c["text"]) for c in it["candidates"])
        f2_skip[iid] = skip
        preds["기존 (근거 검증 통과)"][iid] = base
        preds["+F1 근거 검증 강화"][iid] = f1
        preds["+F2 호출 전 거르기"][iid] = base and not skip
        preds["+F1+F2"][iid] = f1 and not skip

    def score(p):
        tp = sum(1 for i, it in items.items() if it["label_contains"] and p[i])
        fp = sum(1 for i, it in items.items() if not it["label_contains"] and p[i])
        pos = sum(1 for it in items.values() if it["label_contains"])
        neg = len(items) - pos
        pr, rc = (tp / (tp + fp) if tp + fp else 0), tp / pos
        f1 = 2 * pr * rc / (pr + rc) if pr and rc else 0
        return {"precision": round(100 * pr, 1), "recall": round(100 * rc, 1), "f1": round(100 * f1, 1),
                "fpr": round(100 * fp / neg, 1), "tp": tp, "fp": fp}

    res = {"methods": {k: score(v) for k, v in preds.items()}, "by_type": {},
           "f2_skipped_by_type": {}}
    for t in P_TYPES + N_TYPES:
        sub = [i for i, it in items.items() if it["type"] == t]
        res["by_type"][t] = {k: sum(1 for i in sub if v[i]) for k, v in preds.items()}
        res["f2_skipped_by_type"][t] = sum(1 for i in sub if f2_skip[i])
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"{'방식':22} {'Precision':>9} {'Recall':>7} {'F1':>6} {'오탐률':>7}")
    for k, m in res["methods"].items():
        print(f"{k:22} {m['precision']:>8}% {m['recall']:>6}% {m['f1']:>5}% {m['fpr']:>6}%")
    print(f"\n{'유형':4} {'이름':14} " + " ".join(f"{k[:12]:>13}" for k in preds) + "  F2로 호출 생략")
    for t in P_TYPES + N_TYPES:
        e = res["by_type"][t]
        print(f"{t:4} {NAMES[t]:14} " + " ".join(f"{e[k]:>13}" for k in preds) + f"  {res['f2_skipped_by_type'][t]:>6}")


if __name__ == "__main__":
    main()
