"""같은 평가셋에 창 해시·시그니처를 돌려 LLM 판정과 한 표로 비교한다 — 로컬 실행.

    python compare_methods.py --eval eval_v1.jsonl --llm-db judge.sqlite3 --run-id base-v1 \
        --signature-db signature.db --out compare.json

- 창 해시: PromptGate/detection/windowhash (운영 배포본), 테스트베드 20종 적재, fakeredis
- 시그니처: PromptGate/detection/signature (운영 배포본) + 운영 규칙 DB(signature.db), 적중 1건 이상이면 차단(운영 규칙)
- LLM: judge.sqlite3의 판정. '근거 검증 통과'(status=ok & contains=1)를 운영 기준으로 쓴다.
- 통합: 창 해시 OR 시그니처 OR LLM
- 정답: P1~P5 포함(150) / N1~N4 미포함(120)
지연은 항목별로 잰다. 창 해시는 fakeredis라 실 Redis보다 느리게 나온다.
"""
import argparse
import json
import sqlite3
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "PromptGate" / "detection"))

P_TYPES = ("P1", "P2", "P3", "P4", "P5")
N_TYPES = ("N1", "N2", "N3", "N4")
NAMES = {"P1": "재작성", "P2": "요약", "P3": "영어 번역", "P4": "구어체", "P5": "형식 변환",
         "N1": "같은 주제", "N2": "비슷하지만 다른 사실", "N3": "후보 잘못 짝지음", "N4": "무관 프롬프트"}


def score(preds, items):
    tp = sum(1 for it in items if it["label_contains"] and preds[it["item_id"]])
    fp = sum(1 for it in items if not it["label_contains"] and preds[it["item_id"]])
    pos = sum(1 for it in items if it["label_contains"])
    neg = len(items) - pos
    p = tp / (tp + fp) if tp + fp else None
    r = tp / pos if pos else None
    f1 = 2 * p * r / (p + r) if p and r else 0.0
    return {"precision": None if p is None else round(100 * p, 1), "recall": round(100 * r, 1),
            "f1": round(100 * f1, 1), "fpr": round(100 * fp / neg, 1), "tp": tp, "fp": fp, "pos": pos, "neg": neg}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", required=True)
    ap.add_argument("--llm-db", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--signature-db", required=True)
    ap.add_argument("--out", default="compare.json")
    ap.add_argument("--allow-partial", action="store_true")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    import fakeredis
    from preprocessing.normalizer import normalize_text
    from signature import engine as signature
    from windowhash import store
    from windowhash.detect import decide, query_text
    from windowhash.ingest import ingest_directory

    signature.configure_database(a.signature_db)
    r = fakeredis.FakeRedis(decode_responses=True)
    ingest_directory(store.connect(":memory:"), r, ROOT / "PromptGate" / "test" / "testbed" / "generated")
    # 저장소 테스트베드는 19종(10번 제외) — 평가 문서 5종은 모두 들어 있다.

    items = [json.loads(x) for x in Path(a.eval).read_text(encoding="utf-8").splitlines() if x.strip()]
    db = sqlite3.connect(a.llm_db)
    db.row_factory = sqlite3.Row
    llm = {row["decision_id"]: dict(row) for row in db.execute("SELECT * FROM judgments WHERE run_id=?", (a.run_id,))}
    missing = [it["item_id"] for it in items if it["item_id"] not in llm]
    if missing and not a.allow_partial:
        raise SystemExit(f"LLM 판정 누락 {len(missing)}건 — 실험 완료 후 실행(중간 집계는 --allow-partial)")
    if missing:
        items = [it for it in items if it["item_id"] in llm]
        print(f"[중간 집계] LLM 판정된 {len(items)}건만 비교")

    wh, sg, lm, lm_raw, t_wh, t_sg, sig_types = {}, {}, {}, {}, [], [], {}
    for it in items:
        text = normalize_text(it["input_text"])
        t = time.perf_counter()
        wh[it["item_id"]] = bool(decide(query_text(r, text)).blocked)
        t_wh.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        hits = signature.query(text)
        t_sg.append((time.perf_counter() - t) * 1000)
        sg[it["item_id"]] = len(hits) > 0
        if hits:
            sig_types[it["item_id"]] = signature.counts(hits)
        row = llm[it["item_id"]]
        lm[it["item_id"]] = row["status"] == "ok" and row["contains"] == 1
        try:
            lm_raw[it["item_id"]] = json.loads(row["raw_output"] or "").get("contains") is True
        except Exception:
            lm_raw[it["item_id"]] = False
    comb = {k: wh[k] or sg[k] or lm[k] for k in wh}
    t_llm = [llm[it["item_id"]]["elapsed_ms"] for it in items if llm[it["item_id"]]["elapsed_ms"]]

    methods = {
        "시그니처": (sg, statistics.mean(t_sg)),
        "Window Hash": (wh, statistics.mean(t_wh)),
        "LLM 단독 (근거 검증 통과)": (lm, statistics.mean(t_llm)),
        "LLM 단독 (모델 판정)": (lm_raw, statistics.mean(t_llm)),
        "통합 (창 해시 ∪ 시그니처 ∪ LLM)": (comb, None),
    }
    res = {"items": len(items), "methods": {}, "by_type": {}, "signature_hits": sig_types}
    for name, (preds, lat) in methods.items():
        res["methods"][name] = {**score(preds, items), "latency_ms_mean": None if lat is None else round(lat, 1)}
    for t in P_TYPES + N_TYPES:
        sub = [it for it in items if it["type"] == t]
        res["by_type"][t] = {"name": NAMES[t], "n": len(sub),
                             **{name: sum(1 for it in sub if preds[it["item_id"]]) for name, (preds, _) in methods.items()}}
    res["sync_latency_ms"] = round(statistics.mean(t_wh) + statistics.mean(t_sg), 1)
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"{'탐지 방식':32} {'Precision':>9} {'Recall':>7} {'F1':>6} {'오탐률':>7} {'평균 지연':>10}")
    for name, m in res["methods"].items():
        lat = "-" if m["latency_ms_mean"] is None else f"{m['latency_ms_mean']:,.1f}ms"
        pr = "-" if m["precision"] is None else f"{m['precision']}%"
        print(f"{name:32} {pr:>9} {m['recall']:>6}% {m['f1']:>5}% {m['fpr']:>6}% {lat:>10}")
    print("\n유형별 '포함'으로 판정한 건수 (P는 많을수록, N은 적을수록 좋음)")
    names = list(methods)
    print(f"{'유형':4} {'이름':14} {'n':>3} " + " ".join(f"{n[:10]:>10}" for n in names))
    for t, e in res["by_type"].items():
        print(f"{t:4} {e['name']:14} {e['n']:>3} " + " ".join(f"{e[n]:>10}" for n in names))
    print(f"\n시그니처 적중 항목: {len(sig_types)}건 {list(sig_types.items())[:6]}")


if __name__ == "__main__":
    main()
