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
from datetime import datetime, timezone
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
from .keywords import load_approved_keywords  # noqa: E402
from .recognizers import PII_RECOGNIZERS  # noqa: E402

RECOGNIZERS: tuple[Recognizer, ...] = PII_RECOGNIZERS


# 마지막으로 규칙을 읽은 시각·출처. /health와 재로딩 응답이 쓴다.
LOADED_AT: str = ""
RULE_SOURCE: str | None = None
# 마지막 로딩에서 올라간 DB 규칙 수와 승인 키워드 수. 키워드는 인식기 하나에 모여 있어 RECOGNIZERS
# 길이로는 셀 수 없다.
DATABASE_RULES: int = 0
KEYWORDS: int = 0
# 키워드 DB 경로와 마지막 로딩 오류. 오류가 있어도 서비스는 뜨고 /health에 드러난다.
KEYWORD_SOURCE: str | None = None
KEYWORD_ERROR: str | None = None


def _current_keyword_recognizer():
    return next((r for r in RECOGNIZERS if r.entity_type == "DOC_KEYWORD"), None)


def _load_keywords(keyword_db: str | None):
    """승인 키워드를 읽는다. **예외를 올리지 않는다** - (인식기, 오류) 를 돌려준다.

    키워드는 시그니처 규칙과 다르게 다룬다. 시그니처 규칙은 로딩 실패가 기동 실패여야 하지만(규칙이 빠진 채로
    도는 것보다 안 뜨는 게 낫다), 키워드는 관리자가 나중에 쌓는 부가 기능이라 **키워드 DB 문제로 탐지 전체가
    멈추면 안 된다**(2026-10-01, 키워드 DB 쓰기 실패로 탐지가 20초 멈춘 사고). 실패하면 쓰던 키워드를 유지하고
    오류를 /health에 드러낸다. 처음 뜰 때 실패하면 키워드 0건으로 뜬다.

    키워드 DB는 시그니처 DB(`/var/lib/detection/`, root 소유라 서비스가 쓸 수 없다)와 **따로** 둔다 -
    정책 DB(`POLICY_DB`)와 같은 방식.
    """
    if not keyword_db or keyword_db.lower() == "off":
        return None, None
    try:
        return load_approved_keywords(keyword_db), None
    except Exception as exc:  # noqa: BLE001 - 어떤 실패든 탐지를 멈추지 않는다
        return _current_keyword_recognizer(), f"{type(exc).__name__}: {exc}"


def configure_database(db_path: str | None, keyword_db: str | None = None) -> int:
    """DB 규칙을 다시 로드한다. ``None``이면 Python PII 인식기만 사용한다.

    **로딩에 성공해 값을 돌려받은 뒤에야 전역을 바꾼다.** 그래서 예외가 나면 쓰던 규칙이 그대로
    남는다 - 재로딩(`/admin/reload-signatures`)이 실패해도 탐지가 멈추지 않는 근거가 여기다.
    """
    global RECOGNIZERS, LOADED_AT, RULE_SOURCE, DATABASE_RULES, KEYWORDS, KEYWORD_SOURCE, KEYWORD_ERROR
    database_recognizers = () if db_path is None else load_database_recognizers(db_path)
    # 키워드 DB는 인자로 안 주면 환경변수 KEYWORD_DB를 쓴다 - 재로딩 엔드포인트·import 시점 로딩이 그대로 동작하게.
    keyword_path = keyword_db if keyword_db is not None else os.environ.get("KEYWORD_DB")
    # 승인 키워드 0건은 정상이다 - None이면 인식기를 넣지 않는다(keywords.load_approved_keywords 참고).
    keyword_recognizer, keyword_error = _load_keywords(keyword_path)
    keyword_recognizers = (keyword_recognizer,) if keyword_recognizer is not None else ()
    RECOGNIZERS = (*PII_RECOGNIZERS, *database_recognizers, *keyword_recognizers)
    LOADED_AT = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    RULE_SOURCE = db_path
    DATABASE_RULES = len(database_recognizers)
    KEYWORDS = len(keyword_recognizer) if keyword_recognizer is not None else 0
    KEYWORD_SOURCE = keyword_path
    KEYWORD_ERROR = keyword_error
    return len(database_recognizers)


# 현재 Detection main.py를 수정하지 않고도 운영 DB를 연결한다. systemd가 SIGNATURE_DB를
# 명시했을 때만 시작 과정에서 로드하며, 경로/스키마/정규식 오류는 숨기지 않고 시작을 실패시킨다.
_configured_db = os.environ.get("SIGNATURE_DB")
if _configured_db and _configured_db.lower() != "off":
    configure_database(_configured_db)


def query(text: str, context: str | None = None) -> list[Hit]:
    """전처리된 텍스트의 적중 목록. (start, end, entity_type) 순 정렬."""
    hits: list[Hit] = []
    for recognizer in RECOGNIZERS:
        hits.extend(recognizer.analyze(text))
    from .contextual_pii import canonical_label, merge_contextual_hits
    entity = canonical_label(context)
    labels = {'KR_DATE_OF_BIRTH': '생년월일', 'PASSWORD': 'password',
              'GENERIC_API_KEY': 'api_key'}
    if entity in labels:
        prefix = labels[entity] + ': '
        for recognizer in RECOGNIZERS:
            if recognizer.entity_type != entity:
                continue
            for hit in recognizer.analyze(prefix + text):
                start, end = hit.start - len(prefix), hit.end - len(prefix)
                if 0 <= start < end <= len(text) and not any(
                        start < old.end and end > old.start for old in hits):
                    hits.append(Hit(hit.entity_type, start, end, hit.score))
    return [Hit(h.entity_type, h.start, h.end, h.score)
            for h in merge_contextual_hits(text, hits, context)]


def counts(hits: list[Hit]) -> dict[str, int]:
    """entity_type별 건수. 로그에는 값 대신 이것만 남긴다."""
    result: dict[str, int] = {}
    for hit in hits:
        result[hit.entity_type] = result.get(hit.entity_type, 0) + 1
    return result


def category_for_hit(hit: Hit) -> str:
    """Return policy category without widening the public Hit contract."""
    for recognizer in RECOGNIZERS:
        if recognizer.entity_type == hit.entity_type:
            return str(getattr(recognizer, "category", "PII")).upper()
    return "PII"
