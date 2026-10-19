"""judge.sqlite3의 판정을 평가셋 정답과 대조해 지표를 낸다.

    python metrics.py --db judge.sqlite3 --eval eval_v1.jsonl --run-id base-v1 [--out metrics.json]

- 포함 유형(P1~P5): 탐지율 = 'ok'이고 contains=1인 비율. 판정 실패(invalid_quote·schema_error·timeout·error)는 놓친 것으로 센다.
  근거 정확 = 탐지했고, 고른 후보가 정답 문서이며 인용 위치가 정답 구간 안에 있는 비율.
- 미포함 유형(N1~N4): 오탐율 = 'ok'이고 contains=1인 비율.
- 위치 편향: 정답 후보가 1·2·3번일 때 포함 유형 탐지율.
- 지연: elapsed_ms 분포(p50/p95), 입출력 토큰 평균.
"""
import argparse
import json
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

P_TYPES = ("P1", "P2", "P3", "P4", "P5")
N_TYPES = ("N1", "N2", "N3", "N4")
NAMES = {"P1": "재작성", "P2": "요약", "P3": "영어 번역", "P4": "구어체", "P5": "형식 변환",
         "N1": "같은 주제", "N2": "비슷하지만 다른 사실", "N3": "후보 잘못 짝지음", "N4": "무관 프롬프트"}


def pct(a, b):
    return round(100 * a / b, 1) if b else None


def overlaps(span, gold):
    s, e = map(int, span.split("-"))
    gs, ge = map(int, gold.split("-"))
    return s < ge and gs < e


def raw_contains(r):
    """모델 원출력의 contains 값(인용 검증과 무관). 형식이 깨졌으면 None."""
    try:
        v = json.loads(r["raw_output"] or "").get("contains")
        return v if isinstance(v, bool) else None
    except Exception:
        return None


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))] if xs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--eval", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", default="metrics.json")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    items = {json.loads(x)["item_id"]: json.loads(x)
             for x in Path(a.eval).read_text(encoding="utf-8").splitlines() if x.strip()}
    db = sqlite3.connect(a.db)
    db.row_factory = sqlite3.Row
    rows = {r["decision_id"]: dict(r) for r in db.execute("SELECT * FROM judgments WHERE run_id=?", (a.run_id,))}
    missing = sorted(set(items) - set(rows))

    by_type = defaultdict(list)
    for iid, it in items.items():
        if iid in rows:
            by_type[it["type"]].append((it, rows[iid]))

    res = {"run_id": a.run_id, "judged": len(rows), "items": len(items), "missing": missing, "types": {}}
    tp = fp = pos_n = neg_n = rtp = rfp = 0
    for t in P_TYPES + N_TYPES:
        pairs = by_type[t]
        st = Counter(r["status"] for _, r in pairs)
        flagged = sum(1 for _, r in pairs if r["status"] == "ok" and r["contains"] == 1)
        raw_flag = sum(1 for _, r in pairs if raw_contains(r) is True)
        entry = {"name": NAMES[t], "n": len(pairs), "status": dict(st), "flagged": flagged,
                 "rate": pct(flagged, len(pairs)), "raw_flagged": raw_flag, "raw_rate": pct(raw_flag, len(pairs))}
        if t in P_TYPES:
            correct = sum(1 for it, r in pairs if r["status"] == "ok" and r["contains"] == 1
                          and r["doc_id"] == it["gold"]["doc_id"] and r["doc_span"]
                          and overlaps(r["doc_span"], it["gold"]["span"]))
            entry["correct_evidence"] = correct
            entry["correct_evidence_rate"] = pct(correct, len(pairs))
            raw_pick = 0
            for it, r in pairs:
                try:
                    o = json.loads(r["raw_output"] or "")
                    raw_pick += int(o.get("contains") is True and o.get("candidate") == it["gold_position"])
                except Exception:
                    pass
            entry["raw_correct_candidate"] = raw_pick
            entry["raw_correct_candidate_rate"] = pct(raw_pick, len(pairs))
            tp += flagged
            rtp += raw_flag
            pos_n += len(pairs)
        else:
            fp += flagged
            rfp += raw_flag
            neg_n += len(pairs)
        res["types"][t] = entry

    res["overall"] = {"recall": pct(tp, pos_n), "false_positive_rate": pct(fp, neg_n),
                      "precision": pct(tp, tp + fp), "tp": tp, "fp": fp, "pos_n": pos_n, "neg_n": neg_n,
                      "raw_recall": pct(rtp, pos_n), "raw_false_positive_rate": pct(rfp, neg_n),
                      "raw_precision": pct(rtp, rtp + rfp)}

    pos_bias = defaultdict(lambda: [0, 0])
    for t in P_TYPES:
        for it, r in by_type[t]:
            k = it["gold_position"]
            pos_bias[k][1] += 1
            pos_bias[k][0] += int(r["status"] == "ok" and r["contains"] == 1)
    res["position_bias"] = {k: {"n": v[1], "recall": pct(v[0], v[1])} for k, v in sorted(pos_bias.items())}

    conf = defaultdict(lambda: [0, 0])
    for t, pairs in by_type.items():
        for it, r in pairs:
            if r["status"] != "ok":
                continue
            right = (r["contains"] == 1) == it["label_contains"]
            conf[r["confidence"]][1] += 1
            conf[r["confidence"]][0] += int(right)
    res["confidence"] = {k: {"n": v[1], "accuracy": pct(v[0], v[1])} for k, v in conf.items()}

    ms = [r["elapsed_ms"] for r in rows.values() if r["elapsed_ms"]]
    tin = [r["tokens_in"] for r in rows.values() if r["tokens_in"]]
    tout = [r["tokens_out"] for r in rows.values() if r["tokens_out"]]
    res["latency_ms"] = {"p50": q(ms, 0.5), "p95": q(ms, 0.95), "max": max(ms) if ms else None,
                         "mean": round(statistics.mean(ms)) if ms else None}
    res["tokens"] = {"in_mean": round(statistics.mean(tin)) if tin else None,
                     "out_mean": round(statistics.mean(tout)) if tout else None,
                     "out_p95": q(tout, 0.95)}
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"판정 {len(rows)}/{len(items)}건, 누락 {len(missing)}")
    print(f"{'유형':6} {'이름':16} {'건수':>4} {'모델판정':>8} {'근거통과':>8} {'근거정확':>8}  상태")
    for t in P_TYPES + N_TYPES:
        e = res["types"][t]
        ce = f"{e.get('correct_evidence_rate', '')}" if t in P_TYPES else ""
        print(f"{t:6} {e['name']:16} {e['n']:>4} {str(e['raw_rate']):>7}% {str(e['rate']):>7}% {ce:>8}  {e['status']}")
    o = res["overall"]
    print(f"모델 판정 기준: 탐지율 {o['raw_recall']}% · 오탐율 {o['raw_false_positive_rate']}% · 정밀도 {o['raw_precision']}%")
    print(f"근거 검증 통과 기준: 탐지율 {o['recall']}% · 오탐율 {o['false_positive_rate']}% · 정밀도 {o['precision']}%")
    print(f"위치 편향: {res['position_bias']}")
    print(f"확신도: {res['confidence']}")
    print(f"지연 ms: {res['latency_ms']} · 토큰: {res['tokens']}")


if __name__ == "__main__":
    main()
