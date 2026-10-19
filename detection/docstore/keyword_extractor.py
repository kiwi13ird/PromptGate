"""기밀 키워드 추출 서비스 - 색인된 문서를 GPU의 LLM에 보내 핵심 기밀 키워드 후보를 뽑는다 (detection-keyword-extractor.service).

설계: docs/pipelines/keyword-detection-design.md §7

흐름:  문서 등록(RDS documents) → 인덱서 색인 완료 → keyword_jobs에 작업(enqueue_job)
       → 이 서비스가 작업을 잡아 RDS normalized_text를 조각내 LLM에 보냄 → 사후 검증 → doc_keywords에 pending
       → 관리자가 승인(HITL) → 재로딩 시 탐지 반영. **여기서는 승인하지 않는다.**

키워드 기준은 **기밀정보**다(2026-10-01 확정): 문서의 핵심 기밀(내부 프로젝트 코드, 미공개 제품·조직, 진행 중 거래 상대,
내부 사건 식별자). 개인정보·공개 회사명·일반 업무어·목록의 행 항목은 뽑지 않는다 - 개인정보는 패턴 검사가 맡는다.

선정 이유(2026-10-13): 후보를 고른 뒤(기존 선별은 그대로) 후보마다 LLM이 '이 표현을 왜 기밀 후보로 골랐는지' 한두 문장을 쓴다.
**근거 문장은 LLM이 쓰지 않는다** - 시스템이 본문에서 키워드가 든 문장을 그대로 잘라 붙인다(항상 원문과 일치). LLM 답은 자동 검사
(용례·키워드·문서 이름에 없는 숫자·영문 이름이 이유에 들어갔는지, 길이)를 거쳐야 쓴다. 통과 못 하거나 LLM이 실패하면 선별 단계의
짧은 이유로 대체하고 reason_check에 사유를 남긴다. 이유가 없어도 키워드 후보 자체는 그대로 올라간다.

GPU가 꺼져 있을 때:
- 작업이 있으면 먼저 GPU 상태(/v1/models)를 본다. 응답이 없으면 작업을 잡지 않고 기다린다 → 작업은 queued로 쌓인다
- 처리 중 GPU가 끊기면 그 작업을 queued로 되돌린다. **시도 횟수를 쓰지 않는다**(문서 탓이 아니다)
- GPU를 켜면 다음 확인(POLL_SECONDS) 때부터 쌓인 작업을 차례로 처리한다. 문서 등록·색인·탐지는 GPU와 무관하게 끝난다
- 상태는 STATUS_PATH 파일에 남기고 탐지 API /health가 읽어 보여준다(대기 건수, GPU 응답 여부, 마지막 확인 시각)
문서 탓 실패(LLM 응답이 JSON이 아님 등)는 시도 횟수를 쓰고 3회면 failed로 멈춘다. 관리자가 retry로 살린다.

실행: python -m docstore.keyword_extractor           환경변수 DETECTION_PG_DSN, KEYWORD_DB, KEYWORD_LLM_URL
      python -m docstore.keyword_extractor --once    대기 작업을 처리하고 끝낸다(GPU가 없으면 바로 끝난다)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("docstore.keyword_extractor")

LLM_BASE = os.environ.get("KEYWORD_LLM_URL", "http://10.0.3.254:9000/v1")
LLM_MODEL = os.environ.get("KEYWORD_LLM_MODEL", "qwen3-8b")
STATUS_PATH = os.environ.get("KEYWORD_EXTRACTOR_STATUS", "/opt/detection/logs/keyword-extractor.status.json")
NEG_CORPUS = os.environ.get("KEYWORD_NEG_CORPUS", "")      # 무관 말뭉치(jsonl의 text 또는 한 줄 한 문장). 없으면 neg_hits NULL
POLL_SECONDS = 30.0
CHUNK_CHARS = 3000
CHUNK_OVERLAP = 200
PER_CHUNK = 5
MAX_KEYWORDS = 10
LLM_TIMEOUT = 120.0
PROMPT_VERSION = "keyword_extract.v1"
REASON_PROMPT_VERSION = "keyword_reason.v4"
KIND_PROMPT_VERSION = "keyword_kind.v1"
EVIDENCE_WIDTH = 120        # 근거 문장 한 개의 최대 글자 수(키워드 둘레로 자름)
MAX_EVIDENCE = 2            # 후보당 근거 문장 수
REASON_WORKERS = 4          # 후보별 이유 호출 동시 수(GPU가 묶어서 처리한다)
REASON_VERSION = f"{REASON_PROMPT_VERSION}+{KIND_PROMPT_VERSION}"      # 저장하는 판 표시(이유 문구 판 + 종류 분류 판)
REASON_MIN, REASON_MAX = 8, 200

SYSTEM = """사내 기밀문서에서 이 회사의 **핵심 기밀**을 가리키는 고유 표현을 고른다.
고른 표현이 직원이 외부 AI 서비스에 입력한 문장에 들어 있으면 그 입력은 차단된다. 그래서 무관한 문장에는 나오지 않을 표현만 고른다.

고를 것:
- 내부 프로젝트 코드·코드명
- 미공개 제품·차기 버전 이름
- 진행 중인 거래·협상·제휴 상대 (비밀 유지 대상)
- 미공개 조직·내부 시스템·내부 프로그램 이름
- 내부 사건·장애 식별자

고르지 말 것:
- 개인정보: 사람 이름, 사번, 연락처, 이메일, 주민번호, 계좌 (별도 규칙이 잡는다)
- 경쟁사·공개된 회사명, 이 회사의 공개된 회사명·제품명
- 표·목록의 행 단위 항목 (고객사명 하나하나, 티켓 번호 하나하나)
- 일반 업무어(보고서, 매출, 계약, 전략, 회의), 공개 기술명(AWS, Kubernetes), 국가·도시명
- 숫자·날짜·금액만으로 된 것, 2~3자 영문 약어

규칙:
- 본문에 글자 그대로 있는 표현만 쓴다. 줄이거나 바꾸지 않는다
- 이 조각에서 최대 5개. 해당 없으면 빈 목록
- importance: high(문서의 중심 기밀) 또는 medium(부수적)
- reason: 무엇인지 15자 안팎
JSON으로만 답한다."""

REASON_SYSTEM = """당신은 기업 보안 담당자를 돕는 도우미입니다. 사내 기밀문서에서 뽑은 '기밀 키워드 후보'가 주어지면, 담당자가 승인할지 판단할 수 있도록 이 후보를 기밀 후보로 선정한 이유를 짧게 설명합니다.
규칙:
- reason: 한국어 한두 문장, 100자 안팎.
  · 첫 문장: 문서 속 용례에서 이 표현이 무엇을 가리키는지를 용례에 있는 내용만으로 쓴다.
  · 둘째 문장: 알려지면 드러나는 정보를 용례에서 확인되는 것(이름·일정·금액·조직·계획 등)으로 구체적으로 쓴다. 용례에 그런 구체 정보가 없으면 둘째 문장은 쓰지 않는다.
- 용례에 없는 역할·장소·금액·이름·의미를 지어내지 않는다. 용례가 표제·목차·항목명뿐이면 '표제로만 나온다'고 사실대로 쓴다.
- '기밀로 분류해야 한다'처럼 결론을 정하거나 접근 제어 같은 조치를 권하지 않는다. 결정은 담당자가 한다.
- 한국어가 아닌 글자(한자·일본어·러시아어 등)를 쓰지 않는다. 표현 자체에 든 글자는 그대로 쓸 수 있다.
- specificity: 이 표현이 이 문서에서만 쓰이는 고유한 이름·코드·값이면 '고유', 일반어·표제·공개된 이름이면 '일반'.
JSON으로만 답한다."""

REASON_SCHEMA = {
    "type": "object",
    "properties": {"reason": {"type": "string", "maxLength": 160},
                   "specificity": {"type": "string", "enum": ["고유", "일반"]}},
    "required": ["reason", "specificity"], "additionalProperties": False,
}

# 표현 종류 분류(별도 짧은 호출). 일반/고유를 한 번에 묻는 것보다 두 방식을 합치는 쪽이 일반 표현을 더 많이 짚는다
# (맹검 평가 합의 라벨 59건: 일반 표현 재현율 설명 호출 안의 판정 14/29 · 종류 분류 16/29 · 합치면 22/29, 고유를 일반으로 잘못 표시 4/21).
KINDS = ["고유 이름·코드", "값·수치", "문서번호·서식", "표제·항목명", "일반어·직무·부서", "공개된 이름"]
UNIQUE_KINDS = {"고유 이름·코드", "값·수치"}
KIND_SYSTEM = """사내 기밀문서에서 뽑은 표현이 어떤 종류인지 고른다. 문서 속 용례에 있는 내용만 보고 판단한다.
종류:
- 고유 이름·코드: 이 문서·조직에서만 쓰이는 프로젝트 코드명, 미공개 제품·조직·시스템 이름, 내부 식별자, 특정 거래 상대 약칭
- 값·수치: 금액·비율·날짜·수량처럼 구체적인 값이 든 표현
- 문서번호·서식: 문서번호, 결재·서식·양식 용어
- 표제·항목명: 제목, 목차, 표의 항목 이름
- 일반어·직무·부서: 어느 조직에나 있는 일반 용어·기술 용어·직무·부서 이름
- 공개된 이름: 이미 공개된 기업·기관·제품·약물 이름
JSON으로만 답한다."""
KIND_SCHEMA = {"type": "object", "properties": {"kind": {"type": "string", "enum": KINDS}},
               "required": ["kind"], "additionalProperties": False}

SCHEMA = {
    "type": "object",
    "properties": {"keywords": {"type": "array", "maxItems": PER_CHUNK, "items": {
        "type": "object",
        "properties": {"keyword": {"type": "string", "maxLength": 100},
                       "importance": {"type": "string", "enum": ["high", "medium"]},
                       "reason": {"type": "string", "maxLength": 60}},
        "required": ["keyword", "importance", "reason"], "additionalProperties": False}}},
    "required": ["keywords"], "additionalProperties": False,
}


class GpuUnavailable(RuntimeError):
    """GPU(LLM 서버)에 닿지 않는다 - 작업을 시도 횟수 없이 되돌린다."""


# ---------------------------------------------------------------- LLM

def gpu_ready(base: str = LLM_BASE, timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/models", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def llm_chat(system: str, user: str, *, base: str = LLM_BASE, timeout: float = LLM_TIMEOUT,
             schema: dict | None = None, name: str = "keywords", max_tokens: int = 600) -> dict:
    body = {
        "model": LLM_MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0, "seed": 0, "max_tokens": max_tokens,
        "response_format": {"type": "json_schema", "json_schema": {"name": name, "schema": schema or SCHEMA}},
        "chat_template_kwargs": {"enable_thinking": False},
    }
    req = urllib.request.Request(f"{base}/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read())
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
        if isinstance(exc, urllib.error.HTTPError) and exc.code < 500:
            raise  # 요청이 잘못됐다 - GPU 문제가 아니다
        raise GpuUnavailable(f"{type(exc).__name__}: {exc}") from exc
    return json.loads(resp["choices"][0]["message"]["content"])


# ---------------------------------------------------------------- 조각·후보·검증

def split_chunks(text: str, size: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """약 size자 조각. 줄바꿈에서 끊고, 경계에 걸친 표현을 놓치지 않게 overlap만큼 겹친다."""
    if len(text) <= size:
        return [text] if text.strip() else []
    chunks, start = [], 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            cut = text.rfind("\n", start + size // 2, end)
            end = cut if cut != -1 else end
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


_ONLY_DIGITS_SYMBOLS = re.compile(r"^[\d\W_]+$")


@dataclass
class Candidate:
    keyword: str
    reason: str
    high: int = 0
    chunks: int = 0
    first: int = 0

    @property
    def rank(self) -> tuple:
        return (-self.high, -self.chunks, self.first)


def _pii_hit(keyword: str) -> bool:
    """개인정보·자격증명 패턴에 걸리면 키워드가 아니다(패턴 검사가 이미 잡는다)."""
    import signature.engine  # noqa: F401 - engine을 먼저 올려야 signature 하위 모듈의 순환 import가 풀린다
    from signature.recognizers import PII_RECOGNIZERS

    return any(r.analyze(keyword) for r in PII_RECOGNIZERS)


def select(raw: list[list[dict]], text: str) -> tuple[list[Candidate], list[dict]]:
    """조각별 LLM 후보 → 검증 → 순위 → 상한. 반환 (남은 것, 버린 것과 사유)."""
    import signature.engine  # noqa: F401
    from detection_service.keyword_store import KeywordError, clean_keyword
    from signature.keywords import fold

    folded = fold(text)
    cands: dict[str, Candidate] = {}
    dropped = []
    for chunk_items in raw:
        seen_here = set()
        for item in chunk_items:
            try:
                kw = clean_keyword(item.get("keyword", ""))
            except KeywordError as exc:
                dropped.append({"keyword": item.get("keyword"), "why": exc.code})
                continue
            key = fold(kw)
            if key in seen_here:
                continue
            pos = folded.find(key)
            if pos == -1:
                dropped.append({"keyword": kw, "why": "본문에 없음"})
                continue
            if _pii_hit(kw):
                dropped.append({"keyword": kw, "why": "개인정보 패턴"})
                continue
            if _ONLY_DIGITS_SYMBOLS.match(kw):
                dropped.append({"keyword": kw, "why": "숫자·기호만"})
                continue
            seen_here.add(key)
            c = cands.setdefault(key, Candidate(kw, (item.get("reason") or "").strip()[:60], first=pos))
            c.chunks += 1
            c.high += item.get("importance") == "high"
    ranked = sorted(cands.values(), key=lambda c: c.rank)
    # 한 후보가 다른 후보를 포함하면(예: "네오보드"와 "네오보드 3.0") 짧은 쪽이 긴 쪽의 매칭을 모두 덮는다 -
    # 둘 다 승인되면 짧은 쪽 기준으로 막히므로, 둘 다 보여 주되 관리자가 판단하게 한다(여기서 자르지 않는다).
    for c in ranked[MAX_KEYWORDS:]:
        dropped.append({"keyword": c.keyword, "why": f"상한 {MAX_KEYWORDS}개 초과"})
    return ranked[:MAX_KEYWORDS], dropped


def reason_llm_chat(system: str, user: str) -> dict:
    """선정 이유 호출 - 같은 서버·같은 설정(온도 0, seed 0, thinking 끔), 출력 틀만 이유용."""
    return llm_chat(system, user, schema=REASON_SCHEMA, name="reason", max_tokens=400)


def kind_llm_chat(system: str, user: str) -> dict:
    """표현 종류 분류 호출(짧은 출력)."""
    return llm_chat(system, user, schema=KIND_SCHEMA, name="kind", max_tokens=60)


_SEGMENT = re.compile(r"[^\n]+")
_SENT_END = re.compile(r"(?<=[.!?。])\s+")


def _segments(text: str) -> list[tuple[int, int]]:
    """줄과 문장 끝(. ! ? 。 뒤 공백)으로 나눈 (시작, 끝). 빈 조각은 뺀다."""
    out = []
    for line in _SEGMENT.finditer(text):
        base, pos = line.start(), 0
        for m in _SENT_END.finditer(line.group(0)):
            if line.group(0)[pos:m.start()].strip():
                out.append((base + pos, base + m.start()))
            pos = m.end()
        if line.group(0)[pos:].strip():
            out.append((base + pos, line.end()))
    return out


def find_evidence(text: str, keyword: str, *, limit: int = MAX_EVIDENCE, width: int = EVIDENCE_WIDTH) -> list[str]:
    """본문에서 키워드가 든 문장을 그대로 잘라 돌려준다(서로 다른 문장 최대 limit개, 첫 등장부터).

    LLM이 쓰는 인용이 아니라 시스템이 원문에서 잘라 오므로 항상 원문과 일치한다. 한 문장이 width보다 길면 키워드 둘레로
    자르고 …를 붙인다. 표시용이라 공백은 한 칸으로 줄인다."""
    import signature.engine  # noqa: F401
    from signature.keywords import fold

    folded, key = fold(text), fold(keyword)
    if not key:
        return []
    segs = _segments(text)
    out, used = [], set()
    pos = folded.find(key)
    while pos != -1 and len(out) < limit:
        seg = next(((a, b) for a, b in segs if a <= pos < b), None)
        if seg is not None and seg not in used:
            used.add(seg)
            a, b = seg
            if b - a > width:
                start = max(a, pos - width // 3)
                end = min(b, start + width)
                start = max(a, end - width)
                piece = ("…" if start > a else "") + text[start:end].strip() + ("…" if end < b else "")
            else:
                piece = text[a:b].strip()
            out.append(re.sub(r"\s+", " ", piece))
        pos = folded.find(key, (seg[1] if seg else pos + 1))
    return out


_REASON_TOKEN = re.compile(r"[0-9][0-9,.]*|[A-Za-z][A-Za-z0-9\-_]{2,}")
_OTHER_SCRIPT = re.compile("[\u3040-\u30ff\u3400-\u9fff\u0400-\u04ff]")    # 가나·한자·키릴 - 8B 모델이 한국어 문장에 섞어 쓰는 글자


def check_reason(reason: str, allowed: str) -> dict:
    """LLM 이유 자동 검사. allowed = 키워드 + 근거 문장 + 문서 이름. 반환 {ok, foreign_tokens, len}.

    - 이유에 든 숫자와 영문 이름(3자 이상)이 allowed 안에 없으면 지어낸 것으로 본다
    - 한국어 문장에 섞인 한자·가나·키릴 글자도 allowed에 없으면 같은 취급(표현 자체에 든 글자는 허용)
    - 이유 길이가 REASON_MIN~REASON_MAX 밖이면 쓰지 않는다"""
    import signature.engine  # noqa: F401
    from signature.keywords import fold

    pool = fold(allowed)
    foreign = []
    for tok in _REASON_TOKEN.findall(reason):
        if fold(tok.rstrip(".,")) not in pool and tok not in foreign:
            foreign.append(tok)
    for ch in dict.fromkeys(_OTHER_SCRIPT.findall(reason)):
        if ch not in allowed:
            foreign.append(ch)
    ok = REASON_MIN <= len(reason.strip()) <= REASON_MAX and not foreign
    return {"ok": ok, "foreign_tokens": foreign[:5], "len": len(reason.strip())}


def explain(kept: list["Candidate"], text: str, doc_id: str, *,
            chat: Callable[[str, str], dict] = reason_llm_chat,
            kind_chat: Callable[[str, str], dict] | None = None) -> list[dict]:
    """후보마다 근거 문장(시스템)과 선정 이유(LLM + 자동 검사), 표현 종류·일반 여부를 만든다. GpuUnavailable은 그대로 올린다.

    - LLM 호출이 JSON 오류 등으로 실패하거나 자동 검사를 통과 못 하면 선별 단계의 짧은 이유로 대체한다(source='short')
    - 일반 여부(specificity)는 '이유 호출 안의 판정'과 '표현 종류 분류 호출'을 합친다: 둘 중 하나라도 일반이면 '일반'.
      종류 호출은 이유와 독립이라, 이유가 대체됐어도 쓴다. 참고 표시일 뿐 승인·차단에는 쓰지 않는다"""
    kchat = kind_chat or kind_llm_chat

    def classify(c: Candidate, user: str) -> str | None:
        try:
            kind = kchat(KIND_SYSTEM, user).get("kind")
        except GpuUnavailable:
            raise
        except Exception:  # noqa: BLE001 - 종류가 없어도 후보·이유는 올린다
            return None
        return kind if kind in KINDS else None

    def merge(base: dict, kind: str | None, inline: str | None) -> dict:
        general = inline == "일반" or (kind is not None and kind not in UNIQUE_KINDS)
        known = inline in ("고유", "일반") or kind is not None
        base["reason_check"] = {**base["reason_check"], "kind": kind,
                                "specificity": ("일반" if general else "고유") if known else None}
        return base

    def one(c: Candidate) -> dict:
        ev = find_evidence(text, c.keyword)
        user = f"문서: {doc_id}\n후보: {c.keyword}\n문서 속 용례:\n" + "\n".join(f"- {e}" for e in ev)
        kind = classify(c, user)
        try:
            out = chat(REASON_SYSTEM, user)
            reason = str(out.get("reason") or "").strip()
            specificity = out.get("specificity") if out.get("specificity") in ("고유", "일반") else None
        except GpuUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - 이유가 없어도 후보는 올린다
            return merge({"evidence": "\n".join(ev), "reason": c.reason,
                          "reason_check": {"ok": False, "source": "short", "error": type(exc).__name__},
                          "reason_version": REASON_VERSION}, kind, None)
        check = check_reason(reason, f"{c.keyword}\n{doc_id}\n" + "\n".join(ev))
        if check["ok"]:
            return merge({"evidence": "\n".join(ev), "reason": reason,
                          "reason_check": {"ok": True, "source": "llm", "foreign_tokens": []},
                          "reason_version": REASON_VERSION}, kind, specificity)
        return merge({"evidence": "\n".join(ev), "reason": c.reason,
                      "reason_check": {"ok": False, "source": "short", "foreign_tokens": check["foreign_tokens"],
                                       "len": check["len"]},
                      "reason_version": REASON_VERSION}, kind, None)

    if not kept:
        return []
    with ThreadPoolExecutor(min(REASON_WORKERS, len(kept))) as pool:
        return list(pool.map(one, kept))


def count_hits(keyword: str, texts: list[str]) -> int:
    import signature.engine  # noqa: F401
    from signature.keywords import fold

    k = fold(keyword)
    return sum(1 for t in texts if k in fold(t))


def load_neg_corpus(path: str) -> list[str] | None:
    if not path or not Path(path).is_file():
        return None
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(json.loads(line)["text"] if line.startswith("{") else line)
    return out


# ---------------------------------------------------------------- RDS

def fetch_document(conn: Any, doc_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("SELECT version, status, index_status, normalized_text FROM documents WHERE doc_id = %s", (doc_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return {"version": row[0], "status": row[1], "index_status": row[2], "text": row[3]}


def fetch_active_texts(conn: Any) -> list[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT normalized_text FROM documents WHERE status = 'active' AND normalized_text IS NOT NULL")
        return [r[0] for r in cur.fetchall()]


# ---------------------------------------------------------------- 작업 하나

def process_job(job: dict, conn: Any, *, chat: Callable[[str, str], dict] = llm_chat,
                neg: list[str] | None = None, reason_chat: Callable[[str, str], dict] | None = None,
                kind_chat: Callable[[str, str], dict] | None = None) -> dict:
    """작업 하나를 처리한다. 결과 dict: outcome = extracted | superseded. GpuUnavailable은 그대로 올린다."""
    from detection_service import keyword_store

    doc = fetch_document(conn, job["doc_id"])
    if doc is None or doc["status"] != "active":
        keyword_store.finish_job(job["id"], "superseded: document missing or retired")
        return {"job": job["id"], "outcome": "superseded"}
    if job["doc_version"] not in (keyword_store.LATEST_VERSION, doc["version"]) or doc["index_status"] != "indexed" \
            or not doc["text"]:
        # 재등록돼 새 버전이 색인 대기 중이다 - 그 색인이 끝나면 인덱서가 새 작업을 넣는다
        keyword_store.finish_job(job["id"], f"superseded: version {job['doc_version']} -> {doc['version']}")
        return {"job": job["id"], "outcome": "superseded"}

    t0 = time.perf_counter()
    chunks = split_chunks(doc["text"])
    raw = []
    for chunk in chunks:
        user = f"문서: {job['doc_id']}\n\n본문:\n<<<\n{chunk}\n>>>"
        raw.append(chat(SYSTEM, user).get("keywords", []))
    kept, dropped = select(raw, doc["text"])
    corpus = fetch_active_texts(conn)
    # 선정 이유: 기본은 같은 서버의 이유용 호출. 시험처럼 chat을 바꿔 넣으면 reason_chat이 없을 때 그 chat을 같이 쓴다
    rchat = reason_chat or (reason_llm_chat if chat is llm_chat else chat)
    kchat = kind_chat or (kind_llm_chat if chat is llm_chat else chat)
    why = explain(kept, doc["text"], job["doc_id"], chat=rchat, kind_chat=kchat)   # GpuUnavailable이면 아무것도 저장하기 전에 작업이 되돌아간다
    import signature.engine  # noqa: F401
    from signature.keywords import fold

    folded = [fold(t) for t in corpus]
    # 문서 수 3칸(doc_count·common_in_docs·doc_count_at)을 reason_check에 같이 넣는다 - 이후 갱신은 인덱서가 한다(keyword_store.refresh_doc_counts)
    items = [{"keyword": c.keyword, "doc_hits": count_hits(c.keyword, corpus),
              "neg_hits": count_hits(c.keyword, neg) if neg is not None else None, **w,
              "reason_check": {**(w.get("reason_check") or {}), **keyword_store.doc_count_fields(c.keyword, folded)}}
             for c, w in zip(kept, why)]
    inserted = keyword_store.add_extracted(job["doc_id"], items)
    refreshed = keyword_store.refresh_reasons(job["doc_id"], items)
    keyword_store.finish_job(job["id"])
    # 키워드 값은 기밀이다 - 로그에는 개수만 남긴다
    return {"job": job["id"], "outcome": "extracted", "chunks": len(chunks), "candidates": len(kept),
            "inserted": len(inserted), "refreshed": refreshed, "dropped": len(dropped),
            "reason_llm": sum(1 for w in why if w["reason_check"]["ok"]),
            "reason_short": sum(1 for w in why if not w["reason_check"]["ok"]),
            "seconds": round(time.perf_counter() - t0, 1)}


# ---------------------------------------------------------------- 반복

def write_status(path: str, **fields) -> None:
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps({**fields, "updated_ts": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
        tmp.replace(p)
    except OSError as exc:
        log.warning("status write failed: %s", exc)


def run_pending(conn: Any, *, ready: Callable[[], bool] = gpu_ready, chat=llm_chat, neg=None,
                status_path: str = STATUS_PATH, reason_chat=None) -> list[dict]:
    """대기 작업을 GPU가 응답하는 동안 처리한다. GPU가 없으면 아무것도 잡지 않고 돌아온다."""
    from detection_service import keyword_store

    results = []
    while True:
        counts = keyword_store.job_counts()
        if not counts["queued"]:
            write_status(status_path, gpu=None, queued=0, failed=counts["failed"])
            return results
        if not ready():
            write_status(status_path, gpu="down", queued=counts["queued"], failed=counts["failed"])
            log.info("GPU not responding - %d job(s) waiting", counts["queued"])
            return results
        write_status(status_path, gpu="up", queued=counts["queued"], failed=counts["failed"])
        job = keyword_store.claim_job()
        if job is None:
            return results
        try:
            res = process_job(job, conn, chat=chat, neg=neg, reason_chat=reason_chat)
        except GpuUnavailable as exc:
            keyword_store.requeue_job(job["id"], f"gpu: {exc}"[:500], count_attempt=False)
            log.warning("GPU dropped during job %s - requeued without attempt", job["id"])
            write_status(status_path, gpu="down", queued=counts["queued"], failed=counts["failed"])
            return results
        except Exception as exc:
            if _is_connection_error(exc):
                keyword_store.requeue_job(job["id"], f"db: {type(exc).__name__}", count_attempt=False)
                raise
            j = keyword_store.requeue_job(job["id"], f"{type(exc).__name__}: {exc}"[:500], count_attempt=True)
            res = {"job": job["id"], "outcome": j["status"], "error": j["error"]}
        log.info("%s", res)
        results.append(res)


def _is_connection_error(exc: BaseException) -> bool:
    names = {c.__name__ for c in type(exc).__mro__}
    return bool(names & {"OperationalError", "InterfaceError"})


def run(dsn: str, stop: threading.Event | None = None, *, poll: float = POLL_SECONDS) -> None:
    from detection_service.pg_store import _default_connect

    stop = stop or threading.Event()
    neg = load_neg_corpus(NEG_CORPUS)
    conn = None
    while not stop.is_set():
        try:
            if conn is None:
                conn = _default_connect(dsn)
            run_pending(conn, neg=neg)
        except Exception as exc:
            log.warning("extractor loop failed: %s", exc)
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
            conn = None
        stop.wait(poll)


def main(argv: list[str] | None = None) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from detection_service import keyword_store
    from detection_service.pg_store import _default_connect

    ap = argparse.ArgumentParser(description="keyword_jobs → LLM keyword extraction → doc_keywords(pending)")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    dsn = os.environ.get("DETECTION_PG_DSN", "").strip()
    if not dsn:
        log.error("DETECTION_PG_DSN is not set")
        return 2
    if not keyword_store.configure_database(os.environ.get("KEYWORD_DB")):
        log.error("keyword DB unavailable: %s", keyword_store.unavailable_reason())
        return 2
    n = keyword_store.recover_running()
    if n:
        log.warning("recovered %d job(s) stuck in 'running'", n)
    if args.once:
        conn = _default_connect(dsn)
        try:
            run_pending(conn, neg=load_neg_corpus(NEG_CORPUS))
        finally:
            conn.close()
        return 0
    run(dsn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
