"""가짜 vLLM(OpenAI 호환) 서버 - 요청의 사실 번호·enum을 보고 정상 출력 또는 악성 출력을 만든다.

mode="good": 문체·자리표시 규칙을 지키는 출력. mode="bad": 숫자 직접·인용 없는 주장·틀린 자리표시 꼴·표본 글 인용·
없는 번호·문서 대상 차단·근거 없는 '높음'·등급 1 사건 빼기 등. fail={"task": "timeout"|"badjson"|"http500"}로 작업별 실패.
받은 요청 본문은 모두 남긴다(유출 시험: 표본 글이 어느 호출에 들어갔는지).
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _ids(facts, pred=lambda f: True):
    return [f["id"] for f in facts if pred(f)]


class FakeLLM:
    def __init__(self, mode: str = "good", fail: dict | None = None, delay: float = 0.0):
        self.mode, self.fail, self.delay = mode, dict(fail or {}), delay
        self.requests: list[dict] = []
        self.samples: list[str] = []
        self._lock = threading.Lock()
        handler = self._handler()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1/chat/completions"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

    def tasks(self) -> list[str]:
        return [r["task"] for r in self.requests]

    # ------------------------------------------------------------ HTTP
    def _handler(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = json.dumps({"data": [{"id": "qwen3-8b"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                body = json.loads(raw)
                task = body["response_format"]["json_schema"]["name"].removeprefix("report_")
                payload = json.loads(body["messages"][1]["content"].split("\n", 1)[1])
                with outer._lock:
                    outer.requests.append({"task": task, "body": raw.decode("utf-8"), "payload": payload,
                                           "system": body["messages"][0]["content"], "temperature": body.get("temperature"),
                                           "seed": body.get("seed"), "thinking": body.get("chat_template_kwargs")})
                    if task == "classify":
                        outer.samples += [it["text"] for it in payload["items"]]
                fail = outer.fail.get(task)
                if fail == "timeout":
                    time.sleep(3.0)
                if fail == "http500":
                    self.send_response(500)
                    self.end_headers()
                    return
                if outer.delay:
                    time.sleep(outer.delay)
                content = "{not json" if fail == "badjson" else json.dumps(
                    getattr(outer, f"{outer.mode}_{task}")(payload), ensure_ascii=False)
                resp = {"choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": len(raw) // 3, "completion_tokens": len(content) // 3,
                                  "total_tokens": len(raw) // 3 + len(content) // 3}}
                data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        return H

    # ------------------------------------------------------------ 정상 출력
    def good_rank(self, p):
        return {"order": [c["id"] for c in p["candidates"]]}

    def good_commentary(self, p):
        out = []
        for s in p["sections"]:
            facts = s["facts"]
            lines = []
            changed = [f for f in facts if f["type"] in ("count", "rate", "time") and f.get("prev") is not None
                       and f["value"] != f["prev"]]
            first = changed[0] if changed else next((f for f in facts if f["type"] in ("count", "rate", "time")), None)
            if first is None:
                continue
            label = first["label"] if not any(ch.isdigit() for ch in first["label"]) else ""
            lines.append({"t": (f"{label} " if label else "") + "{%s|변화}" % first["id"] if changed else "{%s}" % first["id"],
                          "c": [first["id"]]})
            share = next((f for f in facts if f["type"] == "share" and f["of"] == first["id"]), None)
            if share:
                who = "{%s}" % share["by"] if share.get("by") else share.get("by_service")
                lines.append({"t": "{%s}가 %s에서 나옴" % (share["id"], who), "c": [share["id"]]})
            out.append({"sec": s["sec"], "lines": lines})
        return {"sections": out}

    def good_narrate(self, p):
        items = []
        for it in p["incidents"]:
            inc = it["incident"]
            iid = inc["id"]
            subs = {f["id"] for f in it["facts"]}
            who = "{%s}" % inc["user"] if inc["user"].startswith("U") else "미식별 사용자"
            doc = ("{%s} 일치로 " % inc["docs"][0]) if inc.get("docs") else ""
            what = "{%s.BLOCK}" % iid if f"{iid}.BLOCK" in subs else "{%s.EVENTS}" % iid
            course = [{"t": f"{who}, {{{iid}.START}}부터 {{{iid}.SPAN}} 동안 {doc}{what}", "c": [iid]}]
            result = {"t": "차단 뒤 결과 바뀜, 마지막 요청 허용" if inc.get("allow_after_block") else "같은 대상 반복",
                      "c": [iid]}
            risk = ({"t": "차단 뒤 허용 {%s.ALLOW|값}, 허용 내용은 확인 안 됨" % iid, "c": [iid]} if inc.get("allow_after_block")
                    else {"t": "허용 없음, 차단 단계 확인", "c": [iid]})
            items.append({"id": iid, "course": course, "result": result, "risk": risk})
        return {"items": items}

    def good_users(self, p):
        out = []
        for it in p["users"]:
            u = it["user"]
            uid = u["id"]
            subs = {f["id"] for f in it["facts"]}
            if f"{uid}.SECRET" in subs:
                t = "{%s.SECRET}" % uid + (" · {%s.RETRY}" % uid if f"{uid}.RETRY" in subs else "")
            elif f"{uid}.CRED" in subs:
                t = "{%s.CRED}" % uid + (" · {%s.RETRY}" % uid if f"{uid}.RETRY" in subs else "")
            else:
                t = "{%s.EVENTS} 기준 참고" % uid
            out.append({"id": uid, "level": u["rule_level"], "why": [{"t": t, "c": [uid]}]})
        return {"users": out}

    def good_recs(self, p):
        cards = {f["id"]: f for f in p["cards"]}
        sec = cards.get("F_SECRET")
        summary = [{"t": "기밀 차단 {F_SECRET|변화}" if sec and sec.get("prev") is not None else "{F_SECRET}", "c": ["F_SECRET"]},
                   {"t": "{F_UNCHECKED}", "c": ["F_UNCHECKED"]},
                   {"t": "{F_TOTAL}", "c": ["F_TOTAL"]}]
        recs = []
        for iss in p["issues"]:
            acts = iss["actions"]
            action = next(iter(acts))
            recs.append({"issue": iss["id"], "action": action, "target": acts[action][0],
                         "line": {"t": "{%s} 관련 조치 확인" % iss["id"], "c": [iss["id"]]}})
        return {"summary": summary, "recs": recs}

    def good_classify(self, p):
        out = []
        for it in p["items"]:
            t = it["text"]
            if "고객" in t:
                cat, sub, task = "CS", "CS_LIST", "FORMAT"
            elif "급여" in t:
                cat, sub, task = "HR", "HR_PAY", "FORMAT"
            elif "계약" in t:
                cat, sub, task = "LEGAL", "LEGAL_CONTRACT", "REVIEW"
            else:
                cat, sub, task = "ETC", "ETC_UNKNOWN", "OTHER"
            out.append({"i": it["i"], "cat": cat, "sub": sub, "task": task})
        return {"items": out}

    def good_doccat(self, p):
        return {"docs": [{"id": d["id"], "cat": "PLAN" if "전략" in d["name"] else "HR" if "채용" in d["name"] else "ETC"}
                         for d in p["docs"]]}

    # ------------------------------------------------------------ 악성 출력 (검사기가 버려야 함)
    def bad_rank(self, p):
        return {"order": [c["id"] for c in reversed(p["candidates"])]}   # 등급 1을 뒤로

    def bad_commentary(self, p):
        out = []
        import re as _re
        runs = [m.group(0) for s in self.samples for m in _re.finditer(r"[가-힣 ]{10,}", s)]
        sample = runs[0][:12].strip() if runs else "홍길동 고객님 연락처"   # 표본 글 그대로 옮기기 시도
        for s in p["sections"]:
            ids = _ids(s["facts"])
            f0 = ids[0] if ids else "F_TOTAL"
            out.append({"sec": s["sec"], "lines": [
                {"t": "기밀 차단 17건 늘어남", "c": [f0]},                  # 숫자 직접 + 방향어
                {"t": "{%s|퍼센트}" % f0, "c": [f0]} if not s["sec"] == "S7" else
                {"t": "{%s} %s" % (f0, sample), "c": [f0]},                 # 틀린 꼴 / 표본 글 인용
                {"t": "검사 결과 대부분 정상", "c": []},                     # 인용 없는 주장
            ]})
        return {"sections": out}

    def bad_narrate(self, p):
        items = []
        for it in p["incidents"]:
            iid = it["incident"]["id"]
            items.append({"id": iid,
                          "course": [{"t": "같은 문서 3번 반복 후 수정 후 재시도", "c": [iid]},
                                     {"t": "{%s.START|변화} 시작" % iid, "c": [iid]}],
                          "result": {"t": "의도적 반복으로 보임", "c": [iid]},
                          "risk": {"t": "문서 유출됨", "c": [iid]}})
        return {"items": items}

    def bad_users(self, p):
        return {"users": [{"id": it["user"]["id"], "level": "높음",
                           "why": [{"t": "{%s.EVENTS} [KR_PHONE_NUMBER] 포함" % it["user"]["id"], "c": [it["user"]["id"]]},
                                   {"t": "{%s.EVENTS} 기준" % it["user"]["id"], "c": [it["user"]["id"]]},
                                   {"t": "{F_LEAK} 반복", "c": [it["user"]["id"]]}]}
                          for it in p["users"]]}

    def bad_recs(self, p):
        docs = [n["id"] for n in p["names"] if n["id"].startswith("D")]
        recs = [{"issue": iss["id"], "action": "BLOCK_USER", "target": docs[0] if docs else "NONE",
                 "line": {"t": "SQL 기록 확인 http://evil.example", "c": [iss["id"]]}} for iss in p["issues"]]
        return {"summary": [{"t": "기밀 차단 17건", "c": ["F_SECRET"]}, {"t": "{F_SECRET}건", "c": []},
                            {"t": "검사 서버가 고의로 막음", "c": ["F_TOTAL"]}], "recs": recs}

    def bad_classify(self, p):
        out = []
        for n, it in enumerate(p["items"]):
            if n % 3 == 0:
                out.append({"i": it["i"], "cat": "CS", "sub": "HR_PAY", "task": "FORMAT"})     # 범주와 안 맞는 하위 유형
            elif n % 3 == 1:
                out.append({"i": it["i"], "cat": "XXX", "sub": "CS_LIST", "task": "FORMAT"})   # 없는 범주 → 버림
            else:
                out.append({"i": "C99", "cat": "CS", "sub": "CS_LIST", "task": "FORMAT"})      # 없는 항목
        return {"items": out}

    def bad_doccat(self, p):
        return {"docs": [{"id": "D99", "cat": "PLAN"}]}
