"""PII/Credential 시그니처 판정기.

`detection_service.pipeline`은 WindowHash가 통과한 전처리 텍스트를 이 모듈에 넘긴다.
이 모듈의 적중 결과는 응답의 `signals`에 실리고, 현재 MVP 정책에서는 한 건 이상 적중하면
`blocked=true`로 반환한다. 실제 차단 집행은 Gateway가 담당한다.

PII 인식기는 Python으로 유지하고 운영 변경이 잦은 Credential·계좌 규칙은 서버 시작 시
SQLite에서 한 번 읽어 메모리에 올린다. 요청 처리 중에는 DB를 조회하지 않는다.

인식기는 아래 `Recognizer` 프로토콜을 만족하며 `recognizers.py`의 기본 목록에 등록한다:

    class KRRRNRecognizer:
        entity_type = "KR_RRN"
        def analyze(self, text: str) -> list[Hit]: ...

`Hit`의 필드명은 Presidio `RecognizerResult`를 따른다(ADR-0008) - Presidio 인식기를 감싸
넣을 때 변환이 필요 없다. 적중 값(매치된 문자열)은 어디에도 담지 않는다(ADR-0006).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

NAME = "Signature"


@dataclass(frozen=True)
class Hit:
    """패턴 적중 하나. start/end는 전처리된 텍스트의 코드포인트 오프셋(ADR-0009, hashdb와 동일)."""

    entity_type: str
    start: int
    end: int
    score: float


class Recognizer(Protocol):
    entity_type: str

    def analyze(self, text: str) -> list[Hit]: ...


# 순환 import를 피하기 위해 Hit/Recognizer 계약을 정의한 뒤 운영 인식기를 불러온다.
from .database_rules import load_database_recognizers  # noqa: E402
from .recognizers import PII_RECOGNIZERS  # noqa: E402

RECOGNIZERS: tuple[Recognizer, ...] = PII_RECOGNIZERS


def configure_database(db_path: str | None) -> int:
    """DB 규칙을 다시 로드한다. ``None``이면 Python PII 인식기만 사용한다."""
    global RECOGNIZERS
    database_recognizers = () if db_path is None else load_database_recognizers(db_path)
    RECOGNIZERS = (*PII_RECOGNIZERS, *database_recognizers)
    return len(database_recognizers)


# 현재 Detection main.py를 수정하지 않고도 운영 DB를 연결한다. systemd가 SIGNATURE_DB를
# 명시했을 때만 시작 과정에서 로드하며, 경로/스키마/정규식 오류는 숨기지 않고 시작을 실패시킨다.
_configured_db = os.environ.get("SIGNATURE_DB")
if _configured_db and _configured_db.lower() != "off":
    configure_database(_configured_db)


def query(text: str) -> list[Hit]:
    """전처리된 텍스트의 적중 목록. (start, end, entity_type) 순 정렬."""
    hits: list[Hit] = []
    for recognizer in RECOGNIZERS:
        hits.extend(recognizer.analyze(text))
    return sorted(hits, key=lambda h: (h.start, h.end, h.entity_type))


def counts(hits: list[Hit]) -> dict[str, int]:
    """entity_type별 건수. 로그에는 값 대신 이것만 남긴다."""
    result: dict[str, int] = {}
    for hit in hits:
        result[hit.entity_type] = result.get(hit.entity_type, 0) + 1
    return result
