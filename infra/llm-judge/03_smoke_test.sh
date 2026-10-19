#!/usr/bin/env bash
# vLLM 동작 확인: 구조화 출력(JSON 스키마)·thinking 끔·temperature 0·반복 시 동일 결과·지연
#   실행: bash 03_smoke_test.sh
#   예시 문장은 평가셋과 무관한 가상 문장이다.
set -euo pipefail
exec /opt/judge/.venv/bin/python - <<'PY'
import json, time, urllib.request

URL = "http://127.0.0.1:8000/v1/chat/completions"
SYSTEM = ("너는 기업 기밀문서 유출 여부를 판정하는 검사기다. [입력]이 [후보] 원문에서 파생됐는지 판정한다. "
          "원문의 구체적 정보(수치·날짜·이름·조건)가 표현이 달라도 담겨 있으면 파생이고, 주제만 같으면 파생이 아니다. "
          "지정된 JSON 하나만 출력한다.")
SCHEMA = {
    "type": "object",
    "properties": {
        "derived": {"type": "boolean"},
        "candidate": {"type": ["integer", "null"]},
        "doc_quote": {"type": ["string", "null"]},
        "input_quote": {"type": ["string", "null"]},
        "evidence": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "low"]},
    },
    "required": ["derived", "candidate", "doc_quote", "input_quote", "evidence", "confidence"],
    "additionalProperties": False,
}
DOC = "우리 회사는 내년 3월 15일에 새 스마트워치 오로라를 전국 직영 매장 스무 곳에서 출시한다. 가격은 29만 9천 원으로 정했다."
CASES = [
    ("파생이어야 함", "오로라 워치 3/15 런칭이고 가격은 299,000원으로 확정이래요"),
    ("파생 아니어야 함", "요즘 스마트워치 신제품 가격대가 30만 원 전후로 형성되는 것 같아요"),
]


def ask(text):
    user = f"[입력]\n<<<\n{text}\n>>>\n\n[후보]\n(1) doc_id=TOY span=0-{len(DOC)}\n<<<\n{DOC}\n>>>"
    body = {
        "model": "qwen3-8b",
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
        "temperature": 0, "top_p": 1, "seed": 0, "max_tokens": 300,
        "chat_template_kwargs": {"enable_thinking": False},
        "response_format": {"type": "json_schema", "json_schema": {"name": "judge", "schema": SCHEMA}},
    }
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    t = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as r:
        resp = json.load(r)
    ms = (time.perf_counter() - t) * 1000
    return resp["choices"][0]["message"]["content"], resp["usage"], ms


ok = True
for label, text in CASES:
    out1, usage, ms1 = ask(text)
    out2, _, ms2 = ask(text)
    parsed = json.loads(out1)
    print(f"--- {label}")
    print(f"입력: {text}")
    print(f"출력: {out1}")
    print(f"토큰 in/out: {usage['prompt_tokens']}/{usage['completion_tokens']} · 지연 {ms1:.0f}ms / 재요청 {ms2:.0f}ms")
    print(f"JSON 파싱: OK · 두 번 요청 결과 동일: {'예' if out1 == out2 else '아니오'}")
    ok &= out1 == out2

print("\n스모크 테스트 완료" + ("" if ok else " (반복 결과가 달랐음 — 기록해 주세요)"))
PY
