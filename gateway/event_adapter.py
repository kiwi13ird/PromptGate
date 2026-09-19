"""Gateway Event(gateway.py가 만드는 dict)에서 hashdb가 검사할 수 있는 텍스트만 뽑아낸다.

`gateway-detection-integration-design.md` §1.2("연결")의 실제 구현. Gateway Event의
`contents[]`는 세 종류가 섞여 나올 수 있다 — "prompt"(항상 `content` 있음), "file"(텍스트
추출 성공 시에만 `content` 있음), "image"(`content` 없음). 검사 가능한 건 `content` 키가
있는 항목뿐이다 — file_id만 있는 참조형 첨부(사용자가 이전에 올린 파일을 이번 프롬프트에서
참조만 하는 경우, `/v1/responses`의 `extract_content()`가 만드는 `{"type":"file","file_id":...}`
형태)는 이 함수가 원리적으로 못 잡는다(§7 미해결 09로 별도 추적 — 새 문제, 여기서 만들지
않는다).

여러 항목이 있으면 줄바꿈으로 이어붙여 하나로 합치고 정규화까지 끝낸 뒤 반환한다 — 이벤트
하나당 `/detect` 호출 한 번이 원칙(§1.2)이라, 항목별로 따로 호출하면 지연 예산이 항목
수만큼 늘어난다.

실제 EC2 배포본에서는 `preprocessing` 패키지 전체가 아니라 `normalizer.py` 파일 하나만
옆에 두고 `from normalizer import normalize_text`로 임포트한다(§1.1) — 이 저장소 안에서는
다른 `src/` 패키지와 같은 관례(예: `hashdb/ingest.py`)로 `preprocessing.normalizer`를 쓴다.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from normalizer import normalize_text  # noqa: E402


def extract_checkable_text(event: dict) -> str:
    # "image" 항목도 `content` 키를 갖지만 값이 dict(원본 content_item)다 - 문자열인
    # 것만 검사 대상으로 삼는다(타입 이름이 아니라 값의 모양으로 판단 - gateway.py의
    # extract_content()가 나중에 새 타입을 추가해도 여기서 따로 목록을 안 늘려도 된다).
    texts = [c["content"] for c in event.get("contents", []) if isinstance(c.get("content"), str) and c["content"]]
    if not texts:
        return ""
    return normalize_text("\n".join(texts))
