"""Gateway Event(gateway.py가 만드는 dict)에서 hashdb가 검사할 수 있는 텍스트만 뽑아낸다.

`gateway-detection-integration-design.md` §1.2("연결")의 실제 구현. Gateway Event의
`contents[]`는 세 종류가 섞여 나올 수 있다 - "prompt"(항상 `content` 있음), "file"(텍스트
추출 성공 시에만 `content` 있음), "image"(`content` 없음). 검사 가능한 건 `content` 키가
있는 항목뿐이다 - file_id만 있는 참조형 첨부(사용자가 이전에 올린 파일을 이번 프롬프트에서
참조만 하는 경우, `/v1/responses`의 `extract_content()`가 만드는 `{"type":"file","file_id":...}`
형태)는 이 모듈이 원리적으로 못 잡는다(§7 미해결 09로 별도 추적 - 새 문제, 여기서 만들지
않는다).

**항목을 이어붙이지 않는다(2026-09-23).** 옛 `extract_checkable_text()`는 모든 항목을
줄바꿈으로 이어 하나의 문자열로 만들어 `/detect`를 한 번만 불렀다. 그 합치기가 탐지를
실제로 망가뜨리는 것을 서버에서 확인했다:

1. **창 해시** - `windowhash.hashing.compact()`는 한글·영문·숫자만 남기므로 구분자로 넣은
   줄바꿈이 흔적 없이 사라진다. 그래서 프롬프트 끝과 파일 머리가 붙어 **어느 쪽 입력에도
   실재하지 않는 창**이 창 길이-1개(29개) 만들어진다. `input_span`·`score`도 합친 좌표라
   원문을 가리키지 못한다.
2. **시그니처(PII)** - `signature.recognizers`의 `negative_contexts`(매치 앞 20자)와
   `required_contexts`(매치 앞뒤 30자)가 경계를 넘어 반대쪽 텍스트를 읽는다. 실측:
   프롬프트 "내 생년월일 기준으로 정리해줘" + 파일 "회의 일정 2024.03.14 확정"은 따로면
   둘 다 적중 없음인데 합치면 `KR_DATE_OF_BIRTH`가 적중한다(없던 차단). 반대로 프롬프트
   "이 문서번호" + 파일 "010-1234-5678"은 파일 단독이면 `KR_PHONE_NUMBER`가 적중하는데
   합치면 **사라진다**(있던 탐지가 소실 - 조용한 미탐).

나누는 비용은 사실상 없다. 창 총수가 그대로라 Redis 조회량이 같고(실측 10p/15,000자:
합침 126.8ms vs 나눔 130.5ms), 늘어나는 건 HTTP 왕복 한 번(Gateway->Detection p50 10.4ms)
뿐이다.

정책(파일은 차단, 프롬프트는 마스킹 같은 출처별 처리)은 여기서 정하지 않는다. 이 모듈은
**출처를 보존한 채 나눠 주기만** 하고, 무엇을 할지는 호출자가 정한다.

실제 EC2 배포본에서는 `preprocessing` 패키지 전체가 아니라 `normalizer.py` 파일 하나만
옆에 두고 `from normalizer import normalize_text`로 임포트한다(§1.1) - 이 저장소 안에서는
다른 `src/` 패키지와 같은 관례(예: `hashdb/ingest.py`)로 `preprocessing.normalizer`를 쓴다.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from normalizer import normalize_text  # noqa: E402


def checkable_parts(event: dict) -> list[dict]:
    """검사할 항목을 **합치지 않고** 하나씩 돌려준다.

    반환하는 dict 하나가 `/detect` 호출 하나에 대응한다.

        index     `contents[]`에서의 위치. `request_id`를 "<event id>#<index>"로 잇는 데 쓴다
        kind      "prompt" | "file" (원본 `type`을 그대로 옮긴다)
        filename  파일 항목이면 파일명, 아니면 None
        text      그 항목만 정규화한 텍스트

    "image" 항목도 `content` 키를 갖지만 값이 dict(원본 content_item)다 - 문자열인 것만
    검사 대상으로 삼는다(타입 이름이 아니라 값의 모양으로 판단 - gateway.py의
    `extract_content()`가 나중에 새 타입을 추가해도 여기서 따로 목록을 안 늘려도 된다).
    """
    parts: list[dict] = []
    for index, item in enumerate(event.get("contents", [])):
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        text = normalize_text(content)
        if not text:  # 보이지 않는 문자뿐이던 항목은 정규화 후 빈 문자열이 된다
            continue
        parts.append({
            "index": index,
            "kind": item.get("type"),
            "filename": item.get("filename"),
            "text": text,
        })
    return parts


def part_request_id(event_request_id: str, index: int) -> str:
    """항목별 판정 기록을 요청 하나로 되묶을 수 있게 만든 번호.

    `#` 앞이 요청 단위 식별자다. Detection의 `request_id`는 최대 200자이고 기본키가 아니므로
    (기본키는 판정마다 새로 만드는 `decision_id`) 한 요청에서 여러 행이 나와도 충돌하지 않는다.
    """
    return f"{event_request_id}#{index}"


def extract_checkable_text(event: dict) -> str:
    """옛 경로(2026-09-23 이전). 항목을 이어붙여 하나의 문자열로 만든다.

    **새 코드는 쓰지 않는다** - 위 docstring의 1·2번 이유로 탐지가 틀어진다. 이 저장소 밖의
    옛 호출부가 깨지지 않게 남겨 둔 것뿐이다.
    """
    texts = [c["content"] for c in event.get("contents", []) if isinstance(c.get("content"), str) and c["content"]]
    if not texts:
        return ""
    return normalize_text("\n".join(texts))
