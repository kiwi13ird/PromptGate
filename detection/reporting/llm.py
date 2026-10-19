"""LLM 호출 - 작업별 호출·JSON 스키마·동시 4·시간 상한 (설계 v2 4.6~4.7, 4.10).

GPU EC2의 vLLM(OpenAI 호환, 10.0.3.254:9000 - 보안 그룹상 Detection만 접근)을 부른다. 모든 호출: 온도 0, 시드 0,
생각 단계 끔, `json_schema`로 출력 강제. 인용 번호·코드는 그 호출에 준 값으로 enum을 만든다 → 없는 번호는 구조상 못 씀.
공통 앞부분(문체·자리표시 규칙)을 모든 호출에 똑같이 두어 vLLM 앞부분 재사용이 되게 한다.

원문(prompt 열)은 어느 호출에도 넣지 않는다. 가린 글(재가림·숫자 지움·400자)은 표본 분류 호출에만 들어간다.

문장 글자 문법(설계 v3 B1·B2, 기본 켬, 끄기 REPORT_LLM_TEXT_GRAMMAR=off): 문장 `t`에 숫자·중괄호를 자리표시 밖에서
못 쓰고, 자리표시 번호·꼴은 그 호출에 준 사실 번호와 그 사실에 맞는 꼴만 쓰게 `pattern`으로 묶는다. 끄면 요청 본문은 전과 같다.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

from . import wording
from .content import CAT_CODES, CAT_NAMES, CATEGORIES, SUB_CODES, TASK_CODES, TASKS
from .facts import FORMS, Facts, RenderError

LLM_URL = os.environ.get("REPORT_LLM_URL", "http://10.0.3.254:9000/v1/chat/completions")
LLM_MODEL = os.environ.get("REPORT_LLM_MODEL", "qwen3-8b")
CALL_TIMEOUT = float(os.environ.get("REPORT_LLM_CALL_TIMEOUT", "150"))
STAGE_LIMIT = float(os.environ.get("REPORT_LLM_STAGE_LIMIT", "420"))
WORKERS = int(os.environ.get("REPORT_LLM_WORKERS", "4"))
PROMPT_DIR = Path(__file__).with_name("prompts")
LEVELS = ("높음", "중간", "낮음")
ACTION_CODES = ("BLOCK_USER", "USER_EVENTS", "DOC_EVENTS", "CREDENTIAL_EVENTS", "KEYWORD_PENDING", "DOC_REGISTER",
                "GATEWAY_SETTINGS", "REQUIRE_ID", "POLICY_CHECK", "SYSTEM_CHECK", "NONE")
MAX_TOKENS = {"commentary": 900, "rank": 200, "narrate": 1300, "users": 1300, "recs": 1300, "classify": 700,
              "doccat": 500}


class LLMError(RuntimeError):
    pass


_OFF_WORDS = ("0", "off", "false", "no")


def text_grammar_on() -> bool:
    """B1·B2 문장 글자 문법. 기본 켬 - 끄는 것은 REPORT_LLM_TEXT_GRAMMAR=off(또는 0·false·no)만.
    검사 18~21·서술 v2와 함께 잰 조합이 기본이고, 꺼진 채 검사·서술만 바뀐 상태가 측정상 가장 나빴다
    (llm-report-v3-llm-yield-2026-10-13 9·10장). 끄면 요청 본문은 전(2026-10-13 운영본)과 같다(서술 시스템 글만 v2)."""
    return os.environ.get("REPORT_LLM_TEXT_GRAMMAR", "").strip().lower() not in _OFF_WORDS


def _load(name: str) -> tuple[str, str]:
    raw = (PROMPT_DIR / f"{name}.txt").read_text(encoding="utf-8")
    first, _, rest = raw.partition("\n")
    if not first.startswith("#v "):
        raise ValueError(f"prompt {name} has no version line")
    return first[3:].strip(), rest.strip()


def system_prompt(task: str) -> tuple[str, str]:
    """(시스템 프롬프트, 판 번호). 공통 앞부분 + 작업 부분."""
    common_v, common = _load("common")
    task_v, body = _load(task)
    common = common.replace("{{BANNED}}", wording.banned_for_prompt())
    body = body.replace("{{CATEGORIES}}", "\n".join(
        f"- {c} {n}: " + " · ".join(f"{s} {sn}" for s, sn in subs) + (f" · {c}_OTHER 기타" if c != "ETC" else "")
        for c, n, subs in CATEGORIES))
    body = body.replace("{{TASKS}}", " · ".join(f"{c} {n}" for c, n in TASKS))
    body = body.replace("{{CATEGORY_LIST}}", " · ".join(f"{c} {CAT_NAMES[c]}" for c in CAT_CODES))
    return f"{common}\n\n{body}", f"{task_v}+{common_v}"


# ---------------------------------------------------------------- 스키마

def _enum(values) -> dict:
    vals = list(dict.fromkeys(values)) or ["NONE"]
    return {"type": "string", "enum": vals}


# 자리표시 밖에서 쓸 수 있는 글자(허용 목록). '숫자만 빼기'로 막으면 모델이 아랍 숫자(۱۷)처럼 다른 숫자 글자로
# 우회한다(2026-10-13 vLLM 0.29.0 탐침). 그래서 한글 음절·영문자·띄어쓰기·문장 부호만 허용한다 - 숫자·중괄호·
# JSON 따옴표·역슬래시·줄바꿈은 자리표시 밖에서 못 쓴다(검사 4·6과 같은 글자를 문법에서 미리 막음).
# 한글 음절은 64자 묶음(UTF-8 앞 두 바이트가 같은 범위)으로 나눠 쓴다: '가-힣' 한 범위로 주면 vLLM 0.29.0 문법 변환이
# 마지막 앞 바이트(ED) 쪽을 잘못 잘라 U+D000~U+D77F(하·허·확·통·패·킹 등)를 막는다(2026-10-13 실측: '허용'→'히용').
_HANGUL = "".join(f"{chr(s)}-{chr(min(s + 63, 0xD7A3))}" for s in range(0xAC00, 0xD7A4, 64))
_TEXT_CHARS = _HANGUL + r"A-Za-z .,·()/:;~'%&+_<>?!*…→←‘’“”ㆍ・\[\]\-–—"
# pattern과 maxLength를 같이 주면 vLLM 0.29.0은 maxLength를 무시한다(탐침) - 길이는 반복 상한으로 건다(전과 같은 120)
_TEXT_MAX = 120


def placeholder_forms(fx: Facts, ids) -> dict[str, tuple[tuple[str, ...], bool]]:
    """번호 → (쓸 수 있는 꼴, 꼴 없이 쓸 수 있는지). 렌더러가 실제로 그릴 수 있는 것만(검사 4와 같은 기준)."""
    out = {}
    for fid in ids:
        if fid not in fx:
            continue
        forms = []
        for form in FORMS.get(fx.get(fid)["type"], ()):
            try:
                fx.render_one(fid, form)
                forms.append(form)
            except RenderError:
                pass
        try:
            fx.render_one(fid, None)
            bare = True
        except RenderError:
            bare = False
        if forms or bare:
            out[fid] = (tuple(forms), bare)
    return out


def text_pattern(ph: dict[str, tuple[tuple[str, ...], bool]]) -> str:
    """B1·B2 문장 글자 문법: (허용 글자 | {그 호출 번호} | {그 호출 번호|맞는 꼴}) 1~120개."""
    alts = []
    for fid in sorted(ph):
        forms, bare = ph[fid]
        if forms:
            alts.append(re.escape(fid) + r"(?:\|(?:%s))%s" % ("|".join(forms), "?" if bare else ""))
        else:
            alts.append(re.escape(fid))
    body = r"[%s]" % _TEXT_CHARS
    if alts:
        body += r"|\{(?:%s)\}" % "|".join(alts)
    return r"^(?:%s){1,%d}$" % (body, _TEXT_MAX)


def line_schema(cites, ph=None) -> dict:
    """문장 하나 {t, c}. ph(번호→꼴)를 주면 t에 글자 문법(B1·B2)을 건다 - 안 주면 전과 같은 스키마."""
    t = {"type": "string", "maxLength": 120}
    if ph is not None:
        t = {"type": "string", "pattern": text_pattern(ph)}
    return {"type": "object",
            "properties": {"t": t,
                           "c": {"type": "array", "items": _enum(cites), "minItems": 1, "maxItems": 4}},
            "required": ["t", "c"], "additionalProperties": False}


def _obj(props: dict, required=None) -> dict:
    return {"type": "object", "properties": props, "required": list(required or props), "additionalProperties": False}


def _arr(item: dict, lo: int, hi: int) -> dict:
    return {"type": "array", "items": item, "minItems": lo, "maxItems": max(lo, hi)}


def schema_commentary(secs: list[str], cites, ph=None) -> dict:
    line = line_schema(cites, ph)
    return _obj({"sections": _arr(_obj({"sec": _enum(secs), "lines": _arr(line, 1, 3)}), 1, len(secs))})


def schema_rank(ids: list[str]) -> dict:
    return _obj({"order": _arr(_enum(ids), min(12, len(ids)), len(ids))})


def schema_narrate(ids: list[str], cites, ph=None) -> dict:
    line = line_schema(cites, ph)
    return _obj({"items": _arr(_obj({"id": _enum(ids), "course": _arr(line, 1, 2), "result": line, "risk": line}),
                               1, len(ids))})


def schema_users(ids: list[str], cites, ph=None) -> dict:
    line = line_schema(cites, ph)
    return _obj({"users": _arr(_obj({"id": _enum(ids), "level": _enum(LEVELS), "why": _arr(line, 1, 3)}), 1, len(ids))})


def schema_recs(issues: list[str], targets: list[str], cites, ph=None) -> dict:
    line = line_schema(cites, ph)
    rec = _obj({"issue": _enum(issues), "action": _enum(ACTION_CODES), "target": _enum([*targets, "NONE"]), "line": line})
    return _obj({"summary": _arr(line, 3, 3), "recs": _arr(rec, 0, len(issues))})


def schema_classify(ids: list[str]) -> dict:
    return _obj({"items": _arr(_obj({"i": _enum(ids), "cat": _enum(CAT_CODES), "sub": _enum(SUB_CODES),
                                     "task": _enum(TASK_CODES)}), len(ids), len(ids))})


def schema_doccat(ids: list[str]) -> dict:
    return _obj({"docs": _arr(_obj({"id": _enum(ids), "cat": _enum(CAT_CODES)}), len(ids), len(ids))})


# ---------------------------------------------------------------- 호출

def call(task: str, payload: dict, schema: dict, *, url: str | None = None, model: str | None = None,
         timeout: float | None = None) -> dict:
    """한 번 부른다. 반환 {'out': JSON, 'ms', 'usage', 'prompt': 판 번호}. 실패하면 예외(호출한 쪽이 그 섹션만 대체)."""
    system, version = system_prompt(task)
    body = {
        "model": model or LLM_MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": "입력:\n" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))}],
        "temperature": 0, "seed": 0, "max_tokens": MAX_TOKENS[task],
        "response_format": {"type": "json_schema", "json_schema": {"name": f"report_{task}", "schema": schema}},
        "chat_template_kwargs": {"enable_thinking": False},
    }
    req = urllib.request.Request(url or LLM_URL, data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    t = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout or CALL_TIMEOUT) as r:
        resp = json.loads(r.read())
    ms = (time.perf_counter() - t) * 1000
    try:
        content = resp["choices"][0]["message"]["content"]
        out = json.loads(content)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMError(f"JSON 오류: {type(exc).__name__}") from exc
    if not isinstance(out, dict):
        raise LLMError("JSON 오류: 객체 아님")
    return {"out": out, "ms": round(ms), "usage": resp.get("usage") or {}, "prompt": version}


def run_parallel(jobs: list[tuple[str, Callable[[], Any]]], *, deadline: float, workers: int = WORKERS,
                 on_done: Callable[[str], None] = lambda name: None) -> dict[str, tuple[str, Any]]:
    """작업 묶음을 동시 workers개로 돌린다. 반환 {이름: ('ok', 결과) | ('error', 예외) | ('deadline', None)}.

    데몬 스레드를 쓴다 - LLM 단계 상한(deadline)을 넘긴 호출은 기다리지 않고 버린다(그 섹션은 대체 문장).
    """
    results: dict[str, tuple[str, Any]] = {}
    queue = list(jobs)
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                name, fn = queue.pop(0)
                late = time.monotonic() >= deadline
                if late:
                    results[name] = ("deadline", None)
            if late:
                on_done(name)
                continue
            try:
                r = ("ok", fn())
            except Exception as exc:  # noqa: BLE001 - 시간 초과·연결 실패·JSON 오류 모두 그 작업만 실패
                r = ("error", exc)
            with lock:
                if name not in results:
                    results[name] = r
            on_done(name)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, min(workers, len(jobs))))]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=max(0.0, deadline - time.monotonic()))
    with lock:
        snap = dict(results)
        for name, _ in jobs:
            snap.setdefault(name, ("deadline", None))
            results.setdefault(name, ("deadline", None))   # 늦게 끝난 스레드가 덮어쓰지 않게
    return snap
