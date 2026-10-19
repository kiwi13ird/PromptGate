"""문서 키워드 인식기 - 관리자가 승인한 키워드가 입력에 그대로 들어 있으면 적중한다.

설계: docs/pipelines/keyword-detection-design.md §4

창 해시는 압축 30자 미만을 원리적으로 못 잡고, 기존 시그니처는 형식이 있는 값(주민번호·전화·토큰)만
잡는다. 프로젝트 코드명·고객사명·내부 시스템명처럼 **짧고 형식이 없지만 그 자체로 기밀인 문자열**을
이 인식기가 맡는다. 요약·재작성해도 고유명사는 대개 남으므로, 창 해시가 놓치는 바꿔 쓴 유출의 일부도
잡는다.

매칭 규칙(2026-10-01 결정):
- **부분 문자열**. 단어 경계는 보지 않는다 - `"대외비"`는 `"대외비밀유지"` 안에서도 적중한다
- 영문 대소문자만 무시한다(ASCII에 한해). 한글은 영향이 없다
- 입력은 탐지 API가 이미 정규화한 텍스트다. 키워드도 저장할 때 같은 정규화를 거친다(keyword_store)

**위치가 입력 좌표와 정확히 같아야 한다.** 지금은 정책상 차단이라 위치를 쓰지 않지만, 누군가
`DOC_KEYWORD` 정책을 MASK로 바꾸면 이 위치가 `mask_spans`가 되어 Gateway가 그대로 가린다. 그래서
`str.casefold()`·`str.lower()`를 쓰지 않는다 - 일부 문자(ß, İ 등)에서 길이가 바뀌어 위치가 밀린다.
ASCII 대문자만 소문자로 바꾸는 `translate`는 길이를 보존한다.

**`category`는 반드시 둔다.** 정책 엔진의 `category_for_hit()`는 `category` 속성이 없는 인식기를
`"PII"`로 간주하고, 지금 정책(`POLICY-PII-MASK`)에 걸려 키워드가 차단이 아니라 **마스킹되어 상류로
나간다**. `"KEYWORD"`이면 맞는 정책이 없어 fail-safe로 차단된다.

DB는 요청 처리 중에 조회하지 않는다. 승인된 키워드를 시작·재로딩 때 한 번 읽어 메모리에 둔다
(`database_rules.load_database_recognizers`와 같은 원칙).

**보호 중지 문서의 키워드는 올리지 않는다**(2026-10-16). 문서 상태의 원본은 RDS `documents.status`인데 탐지 API는
RDS를 보지 않는다. 그래서 인덱서가 상태를 키워드 DB `doc_states`에 옮겨 두고(keyword_store.sync_doc_states),
바뀌면 `/admin/reload-signatures`를 부른다. 여기서는 `doc_states`에 **보호 중이 아닌 것으로 적힌** 문서의 키워드만
뺀다 - 상태를 모르는 문서(표가 없거나 아직 안 옮긴 문서)의 키워드는 그대로 쓴다(모를 때 탐지를 줄이지 않는다).
키워드 행·승인 상태는 건드리지 않으므로 다시 보호하면 다음 재로딩에 돌아온다.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from .engine import Hit

ENTITY_TYPE = "DOC_KEYWORD"
CATEGORY = "KEYWORD"

# ASCII 대문자 -> 소문자. 길이를 보존한다(위 docstring 참고).
_ASCII_LOWER = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}


def fold(text: str) -> str:
    """매칭용으로 접는다. 길이가 바뀌지 않는다."""
    return text.translate(_ASCII_LOWER)


class KeywordRecognizer:
    entity_type = ENTITY_TYPE
    category = CATEGORY

    def __init__(self, keywords: Iterable[str]) -> None:
        # 같은 키워드가 여러 문서에서 승인될 수 있다. 매칭은 문자열 단위라 하나로 접는다.
        self._keywords = tuple(sorted({fold(k) for k in keywords if k}))

    def __len__(self) -> int:
        return len(self._keywords)

    def analyze(self, text: str) -> list[Hit]:
        folded = fold(text)
        hits: list[Hit] = []
        for keyword in self._keywords:
            start = folded.find(keyword)
            while start != -1:
                hits.append(Hit(ENTITY_TYPE, start, start + len(keyword), 1.0))
                start = folded.find(keyword, start + 1)
        return hits


def load_approved_keywords(db_path: str | Path) -> KeywordRecognizer | None:
    """승인된 키워드로 인식기를 만든다(보호 중지 문서의 것은 뺀다). 표가 아직 없거나 쓸 키워드가 0건이면 None.

    키워드 0건은 **정상 상태**다(문서를 막 등록했거나 아직 승인 전). 그래서 시그니처 규칙과 달리
    "0건이면 기동 실패"로 다루지 않는다. 표는 탐지 API가 뜰 때 keyword_store가 만드는데, 이 함수는
    엔진 import 시점에 먼저 불릴 수 있으므로 표가 없을 수도 있다.
    """
    path = Path(db_path)
    if not path.is_file():
        return None
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'doc_keywords'"
        ).fetchone()
        if not exists:
            return None
        has_states = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'doc_states'"
        ).fetchone()
        sql = "SELECT keyword FROM doc_keywords WHERE status = 'approved'"
        if has_states:
            sql += (" AND NOT EXISTS (SELECT 1 FROM doc_states s"
                    " WHERE s.doc_id = doc_keywords.doc_id AND s.status <> 'active')")
        rows = connection.execute(sql).fetchall()
    finally:
        connection.close()
    recognizer = KeywordRecognizer(row[0] for row in rows)
    return recognizer if len(recognizer) else None
