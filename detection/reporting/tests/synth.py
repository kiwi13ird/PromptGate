"""합성 자료 + 가짜 DB 연결 - 운영 RDS 없이 aggregate.collect·content.build_items를 끝까지 돌린다.

가짜 연결은 aggregate·content의 SQL 문장(같은 문자열)을 알아보고 메모리 표에서 같은 행을 돌려준다.
실행한 SQL을 모두 남긴다(내용 경향을 끄면 가린 글 열을 읽지 않는지 확인용). 값은 전부 가짜.
"""

from __future__ import annotations

import itertools
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from reporting import aggregate as ag
from reporting import content as ct

KST = timezone(timedelta(hours=9))
_seq = itertools.count(1)


def kst(s: str) -> datetime:
    """'2026-10-05 10:00:00' (한국 시각) → UTC aware."""
    return datetime.fromisoformat(s).replace(tzinfo=KST).astimezone(timezone.utc)


def ev(t: str, client: str, llm: str, action: str, ct_: str = "prompt", *, rc: str | None = None,
       docs=(), ents: dict | None = None, deg: bool = False, endpoint: str = "", pms: float | None = None,
       fid: str | None = None, rid: str | None = None, delay_s: float = 2.0, eid: str | None = None) -> dict:
    n = next(_seq)
    dets = [{"detector": "WINDOW_HASH", "doc": d, "ents": []} for d in docs]
    if ents:
        dets.append({"detector": "SIGNATURE", "doc": None,
                     "ents": [{"entity_type": k, "count": v} for k, v in ents.items()]})
    occurred = kst(t)
    return {"event_id": eid or f"ev-{n:04d}", "root": rid if rid is not None else f"req-{n:04d}",
            "occurred_at": occurred, "created_at": occurred + timedelta(seconds=delay_s), "client_id": client,
            "target_llm": llm, "final_action": action, "ct": ct_, "rc": rc, "fid": fid, "deg": deg,
            "ep_v1": endpoint.startswith("/v1/"), "ep_rpc": endpoint.startswith("/claudeai-rpc/"), "pms": pms,
            "dets": dets}


def doc_text(doc: str) -> str:
    """가짜 보호 문서 본문(문단 20개, 문단마다 번호가 달라 서로 겹치지 않음)."""
    return "\n".join(f"{doc} 문서 {i}번째 문단은 사업 계획과 보안 점검 결과를 정리한 내용입니다." for i in range(1, 21))


def doc_prompt(doc: str, rate: float) -> str:
    """문서 본문에서 문단 (1 - rate) 몫을 전혀 다른 글로 바꾼 입력 - '문서와 같은 글자'가 대략 rate가 된다."""
    lines = doc_text(doc).split("\n")
    k = round(len(lines) * (1 - rate))
    for j in range(k):
        i = int((j + 0.5) * len(lines) / k)
        lines[i] = f"회의 메모 {i}: 다음 주 화요일 오후 본관 회의실 일정 안내와 준비물 목록"
    return "\n".join(lines)


def dec(root: str, t: datetime, *, service: str = "ChatGPT", ct_: str = "prompt", doc: str | None = None,
        match_rate: float | None = None, filename: str | None = None, total_ms: float = 20.0,
        err: bool = False, masked: str | None = None, findings=None, order: int | None = None, suffix: str = "",
        prompt: str | None = None) -> dict:
    """match_rate: 해시 근거 비율(탐지 점수). 문서가 있으면 입력 본문을 그 비율쯤 같은 글로 만든다('문서와 같은 글자' 계산용)."""
    if prompt is None and doc and match_rate is not None:
        prompt = doc_prompt(doc, match_rate)
    return {"request_id": root + suffix, "ts": t, "service": service, "content_type": ct_, "doc_id": doc,
            "match_rate": match_rate, "filename": filename, "total_ms": total_ms,
            "hash_status": "error" if err else "ok", "signature_status": "ok", "masked_text": masked,
            "findings": findings, "block_order": order, "prompt": prompt}


class _Cur:
    def __init__(self, rows, cols):
        self._rows = rows
        self.description = None if cols is None else [type("C", (), {"name": c})() for c in cols]

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


def _pct(xs, q):
    return ag.percentile(xs, q)


class FakeConn:
    def __init__(self, events=(), decisions=(), documents=(), admin=(), gateway=(), aliases=None):
        self.events, self.decisions = list(events), list(decisions)
        self.documents, self.admin, self.gateway = list(documents), list(admin), list(gateway)
        self.aliases = aliases
        self.sql: list[str] = []

    # psycopg.connect(...) as conn 흉내
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def rollback(self):
        pass

    def _doc_text(self, doc: str) -> str:
        own = next((d.get("normalized_text") for d in self.documents if d.get("doc_id") == doc), None)
        return own if isinstance(own, str) else doc_text(doc)

    def _dec(self, lo, hi, services, pattern):
        suffix = pattern.lstrip("%")
        return [d for d in self.decisions if lo <= d["ts"] < hi and d["service"] in services
                and not d["request_id"].endswith(suffix)]

    def execute(self, sql, params=()):
        self.sql.append(sql)
        p = list(params)
        s = sql.strip()
        if s.upper().startswith("SET "):
            return _Cur([], None)
        if sql == ag.EVENTS_SQL:
            t0, t1 = p
            rows = sorted((e for e in self.events if t0 <= e["occurred_at"] < t1), key=lambda e: (e["occurred_at"], e["event_id"]))
            cols = ["event_id", "root", "occurred_at", "created_at", "client_id", "target_llm", "final_action", "ct", "rc",
                    "fid", "deg", "ep_v1", "ep_rpc", "pms", "prompt_hash", "dets"]
            # prompt_hash: 실제 SQL은 판정 기록 본문의 md5(질문만) - 가짜 자료는 이벤트에 직접 둔다(없으면 null)
            return _Cur([tuple(e.get(c) if c == "prompt_hash" else e[c] for c in cols) for e in rows], cols)
        if sql == ag.DECISION_ROOTS_SQL:
            g = defaultdict(list)
            for d in self._dec(*p):
                g[d["request_id"].split("#")[0]].append(d)
            rows = []
            for root, ds in g.items():
                exts = [d["filename"].rsplit(".", 1)[-1].lower() for d in ds
                        if d["content_type"] == "file" and d["filename"] and "." in d["filename"]]
                rows.append((root, max(d["service"] for d in ds), max(d["content_type"] for d in ds),
                             max(exts) if exts else None, any(d["hash_status"] == "error" for d in ds), len(ds)))
            return _Cur(rows, ["root", "svc", "ct", "ext", "err", "n"])
        if sql == ag.SAME_EVENTS_SQL:            # 대시보드 이벤트 원본(문서 구간 일치 위치는 판정 기록과 같게)
            (ids,) = p
            rows = []
            for e in self.events:
                if e["event_id"] not in ids:
                    continue
                dets = []
                for d in e["dets"]:
                    if d["detector"] != "WINDOW_HASH":
                        dets.append({"detector": d["detector"]})
                        continue
                    r = next((x for x in self.decisions if x["request_id"] == e["root"] and x["doc_id"] == d["doc"]), None)
                    n_in = len(r["prompt"]) if r and r.get("prompt") else 1
                    dets.append({"detector": "WINDOW_HASH", "matched_document_id": d["doc"], "score": (r or {}).get("match_rate"),
                                 "input_location": {"char_start": 0, "char_end": n_in},
                                 "matched_location": {"char_start": 0, "char_end": len(self._doc_text(d["doc"]))}})
                rows.append((e["event_id"], {"event_id": e["event_id"], "request_id": e["root"] or None,
                                             "detection_outcome": "MATCH" if dets else "NO_MATCH", "detections": dets}))
            return _Cur(rows, ["event_id", "event"])
        if sql == ag.SAME_DECISIONS_SQL:
            limit, rids = p
            rows = []
            for d in self.decisions:
                if d["request_id"] not in rids:
                    continue
                pr = d.get("prompt")
                rows.append((d["request_id"], d["ts"], "windowhash" if d["doc_id"] else None, d["doc_id"],
                             f"0-{len(self._doc_text(d['doc_id']))}" if d["doc_id"] else None,
                             f"0-{len(pr)}" if pr else None, pr is not None, None,
                             None if pr is None else len(pr), pr if pr is not None and len(pr) <= limit else None))
            return _Cur(rows, ["request_id", "ts", "decided_by", "doc_id", "doc_span", "input_span", "prompt_kept",
                               "document_ref", "prompt_chars", "prompt"])
        if sql == ag.SAME_DOCUMENTS_SQL:
            limit, ids = p
            rows = [(i, 1, len(self._doc_text(i)), self._doc_text(i)) for i in ids]
            return _Cur(rows, ["doc_id", "version", "normalized_chars", "normalized_text"])
        if sql == ag.SAME_VERSIONS_SQL:
            return _Cur([], ["doc_id", "version", "normalized_sha256", "normalized_chars", "normalized_text"])
        if sql == ag.DECISION_STATS_SQL:
            ds = self._dec(*p)
            ms = [d["total_ms"] for d in ds]
            err = len({d["request_id"].split("#")[0] for d in ds if d["hash_status"] == "error"})
            return _Cur([(len(ds), _pct(ms, 0.5), _pct(ms, 0.95), err)], ["rows", "p50", "p95", "err_roots"])
        if sql == ag.DECISION_ONLY_SQL:
            ev_roots = {e["root"] for e in self.events if e["root"]}
            g = {}
            for d in self._dec(*p):
                g.setdefault(d["request_id"].split("#")[0], d)
            cnt = defaultdict(int)
            for root, d in g.items():
                if root not in ev_roots:
                    cnt[(d["service"], d["content_type"] or "")] += 1
            return _Cur([(s, c, n) for (s, c), n in cnt.items()], ["svc", "ct", "n"])
        if sql == ag.DOCUMENTS_SQL:
            cols = ["doc_id", "format", "status", "index_status", "classification", "registered_at"]
            return _Cur([tuple(d.get(c) for c in cols) for d in self.documents], cols)
        if sql == ag.ADMIN_SQL:
            t0, t1 = p
            cols = ["occurred_at", "admin_id", "action", "target_type", "result"]
            return _Cur([tuple(r[c] for c in cols) for r in self.admin if t0 <= r["occurred_at"] < t1], cols)
        if sql == ag.GATEWAY_SETTINGS_SQL:
            t1, t0, _ = p
            before = [g for g in self.gateway if g["updated_at"] < t0]
            last = max(before, key=lambda g: g["version"]) if before else None
            rows = [g for g in self.gateway if (t0 <= g["updated_at"] < t1) or g is last]
            cols = ["version", "settings", "updated_by", "updated_at"]
            return _Cur([tuple(g[c] for c in cols) for g in sorted(rows, key=lambda g: g["version"])], cols)
        if "to_regclass('dashboard_client_aliases')" in sql:
            return _Cur([(self.aliases is not None,)], ["exists"])
        if "from dashboard_client_aliases" in sql:
            return _Cur(list((self.aliases or {}).items()), ["client_id", "alias"])
        if sql == ag.FIRST_BY_CLIENT_SQL:
            first: dict = {}
            for e in self.events:
                c = e["client_id"]
                first[c] = min(first.get(c, e["occurred_at"]), e["occurred_at"])
            return _Cur(list(first.items()), ["client_id", "first"])
        if sql == ct.POOL_SQL:
            lo, hi, services, pattern, roots = p
            g = defaultdict(int)
            for d in self._dec(lo, hi, services, pattern):
                r = d["request_id"].split("#")[0]
                if d["masked_text"] is not None and r in roots:
                    g[(r, d["content_type"])] += 1
            return _Cur([(r, c, n) for (r, c), n in g.items()], ["root", "ct", "n"])
        if sql == ct.TEXT_SQL:
            lo, hi, services, pattern, roots = p
            rows = []
            for d in self._dec(lo, hi, services, pattern):
                r = d["request_id"].split("#")[0]
                if d["masked_text"] is not None and r in roots:
                    fs = [{"t": f["entity_type"], "r": f["replacement"]} for f in (d["findings"] or [])] or None
                    ext = d["filename"].rsplit(".", 1)[-1].lower() if d["filename"] and "." in d["filename"] else None
                    rows.append((r, d["content_type"], d["block_order"], d["ts"], d["masked_text"], fs, ext))
            rows.sort(key=lambda x: (x[0], x[2] is None, x[2] or 0, x[3]))
            return _Cur(rows, ["root", "ct", "block_order", "ts", "masked_text", "fs", "ext"])
        raise AssertionError(f"unexpected SQL: {s[:80]}")


# ---------------------------------------------------------------- 손으로 라벨한 사건 시나리오 (test_incidents)

A, B, C, D, E = "chrome-aaaa-0001", "chrome-bbbb-0002", "chrome-cccc-0003", "chrome-dddd-0004", "chrome-eeee-0005"
X = ag.UNKNOWN_CLIENT


def incident_fixture() -> tuple[list[dict], list[dict]]:
    """(이벤트 원시 행, 판정 기록). 기대 사건표는 test_incidents.py에 손으로 적어 둠."""
    E_ = []
    add = lambda *a, **k: E_.append(ev(*a, **k)) or E_[-1]
    # 사용자 A - ChatGPT 기밀 차단 → 문서와 같은 글자 낮아짐 → 마스킹 → 허용 / 29:59·30:01 경계 / 다른 서비스 같은 문서
    a1 = add("2026-10-05 10:00:00", A, "ChatGPT", "BLOCK", "file", rc="doc_excerpt", docs=["01_전략_보고서"], eid="a1")
    a2 = add("2026-10-05 10:02:00", A, "ChatGPT", "BLOCK", "file", rc="doc_excerpt", docs=["01_전략_보고서"], eid="a2")
    add("2026-10-05 10:03:00", A, "ChatGPT", "MASK", "prompt", rc="pii", ents={"KR_PHONE_NUMBER": 2}, eid="a3")
    add("2026-10-05 10:05:00", A, "ChatGPT", "ALLOW", "prompt", eid="a4")
    add("2026-10-05 10:20:00", A, "ChatGPT", "ALLOW", "prompt", eid="a5")
    add("2026-10-05 10:40:00", A, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["01_전략_보고서"], eid="a6")
    add("2026-10-05 11:09:59", A, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["01_전략_보고서"], eid="a7")
    add("2026-10-05 11:40:00", A, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["01_전략_보고서"], eid="a8")
    add("2026-10-05 11:45:00", A, "Gemini", "BLOCK", "prompt", rc="doc_excerpt", docs=["01_전략_보고서"], eid="a9")
    add("2026-10-05 11:50:00", A, "Gemini", "BLOCK", "prompt", rc="pii", ents={"KR_RRN": 1}, eid="a10")
    # 사용자 B - Claude, 한국 자정을 넘는 마스킹 반복 / 인증정보 마스킹 → 차단 → 허용
    add("2026-10-05 23:55:00", B, "Claude", "MASK", "prompt", rc="pii", ents={"EMAIL_ADDRESS": 1}, eid="b1")
    add("2026-10-06 00:10:00", B, "Claude", "MASK", "prompt", rc="pii", ents={"EMAIL_ADDRESS": 1}, eid="b2")
    add("2026-10-06 00:30:00", B, "Claude", "MASK", "prompt", rc="pii", ents={"GITHUB_TOKEN": 1}, eid="b3")
    add("2026-10-06 00:31:00", B, "Claude", "BLOCK", "prompt", rc="pii", ents={"GITHUB_TOKEN": 1}, eid="b4")
    add("2026-10-06 00:35:00", B, "Claude", "ALLOW", "prompt", eid="b5")
    # 사용자 C - 검사 없이 통과 반복 / 검사 불가 차단 → 허용
    add("2026-10-07 09:00:00", C, "ChatGPT", "ALLOW", "file", rc="file_uninspectable_image", eid="c1")
    add("2026-10-07 09:10:00", C, "ChatGPT", "ALLOW", "file", rc="file_uninspectable_image", eid="c2")
    add("2026-10-07 09:15:00", C, "ChatGPT", "BLOCK", "file", rc="file_uninspectable_other", eid="c3")
    add("2026-10-07 09:16:00", C, "ChatGPT", "ALLOW", "prompt", eid="c4")
    # 식별 안 됨 - 같은 서비스·같은 대상만 (사이에 다른 서비스 이벤트가 끼어도 묶임)
    add("2026-10-08 14:00:00", X, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["02_채용_평가서"], eid="x1")
    add("2026-10-08 14:05:00", X, "Gemini", "MASK", "prompt", rc="pii", ents={"KR_PHONE_NUMBER": 1}, eid="x2")
    add("2026-10-08 14:20:00", X, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["02_채용_평가서"], eid="x3")
    add("2026-10-08 14:25:00", X, "ChatGPT", "ALLOW", "prompt", eid="x4")
    add("2026-10-08 14:30:00", X, "Claude", "BLOCK", "prompt", rc="doc_excerpt", docs=["02_채용_평가서"], eid="x6")
    add("2026-10-08 15:00:00", X, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["02_채용_평가서"], eid="x5")
    # 사용자 D - 문제 없는 허용만 / 사용자 E - 서로 다른 문서 2종
    add("2026-10-09 09:00:00", D, "Gemini", "ALLOW", "prompt", eid="d1")
    add("2026-10-09 09:30:00", D, "Gemini", "ALLOW", "prompt", eid="d2")
    add("2026-10-09 10:00:00", E, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["01_전략_보고서"], eid="e1")
    add("2026-10-09 13:00:00", E, "ChatGPT", "BLOCK", "prompt", rc="doc_excerpt", docs=["03_협상_전략"], eid="e2")
    decs = [dec(a1["root"], a1["occurred_at"], ct_="file", doc="01_전략_보고서", match_rate=1.0, filename="a.docx"),
            dec(a2["root"], a2["occurred_at"], ct_="file", doc="01_전략_보고서", match_rate=0.8, filename="a.docx")]
    return E_, decs
