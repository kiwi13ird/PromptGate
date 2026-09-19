"""SQLite에서 활성화된 Signature 규칙을 한 번 읽어 메모리 인식기로 만든다."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from .engine import Hit


class DatabaseRuleRecognizer:
    def __init__(
        self,
        *,
        rule_id: str,
        entity_type: str,
        pattern: str,
        score: float,
        context_keywords: tuple[str, ...],
        requires_context: bool,
    ) -> None:
        self.rule_id = rule_id
        self.entity_type = entity_type
        self._pattern = re.compile(pattern, re.IGNORECASE)
        self._score = score
        self._keywords = context_keywords
        self._requires_context = requires_context

    def _is_bound_to_context(self, text: str, match: re.Match[str]) -> bool:
        if not self._keywords:
            return False
        labels = "|".join(re.escape(value) for value in sorted(self._keywords, key=len, reverse=True))
        prefix = text[max(0, match.start() - 100) : match.start()]
        return bool(re.search(rf"[\"']?(?:{labels})[\"']?\s*(?::|=)\s*[\"']?$", prefix, re.IGNORECASE))

    def analyze(self, text: str) -> list[Hit]:
        hits: list[Hit] = []
        for match in self._pattern.finditer(text):
            if self._requires_context and not self._is_bound_to_context(text, match):
                continue
            hits.append(Hit(self.entity_type, match.start(), match.end(), self._score))
        return hits


def load_database_recognizers(db_path: str | Path) -> tuple[DatabaseRuleRecognizer, ...]:
    """DB를 요청마다 조회하지 않고 서버 시작 시 한 번 로드한다."""
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Signature DB not found: {path}")

    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT rule_id, entity_type, pattern, score, context_keywords, requires_context
            FROM signature_rules
            WHERE enabled = 1
            ORDER BY rule_id
            """
        ).fetchall()
    finally:
        connection.close()

    if not rows:
        raise RuntimeError(f"Signature DB has no enabled rules: {path}")

    recognizers = []
    for row in rows:
        keywords = tuple(value.strip() for value in (row["context_keywords"] or "").split(",") if value.strip())
        recognizers.append(
            DatabaseRuleRecognizer(
                rule_id=row["rule_id"],
                entity_type=row["entity_type"],
                pattern=row["pattern"],
                score=float(row["score"]),
                context_keywords=keywords,
                requires_context=bool(row["requires_context"]),
            )
        )
    return tuple(recognizers)
