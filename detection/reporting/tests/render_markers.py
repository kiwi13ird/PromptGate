"""보고서 HTML에 출처 표시가 없는지 보는 검사 - 시험 공용 (2026-10-12 사용자 지적: 보고서는 일반 보고서처럼 읽혀야 함).

옛 보고서에 있던 표시: 문장 앞 'LLM'·'집계'·'일부 집계' 이름표(tag-llm·tag-sql), 문장 끝 인용 번호(cite), LLM 문장 블록(llm),
머리·바닥글의 '작성 …', 사건 '순위: LLM·규칙', 사용자 등급 옆 '규칙'·'LLM'. 이 표시는 생성 기록 JSON에만 남긴다.
"""

from __future__ import annotations

import html as _html
import re

OLD_CLASSES = ("tag-llm", "tag-sql", "cite", "llm")
OLD_STRINGS = ("LLM", "일부 집계", "집계 문장", "자동 작성", "작성", "순위:", "규칙 높음", "근거")
FACT_ID_PATTERNS = (r"\{[A-Z]", r"\b[FGK]_[A-Z0-9_]+", r"\b[IUDREK]\d{1,3}\b")


def strip_style(doc: str) -> str:
    return re.sub(r"<style>.*?</style>", "", doc, flags=re.S)


def visible_text(doc: str) -> str:
    """태그를 떼고 글만(SVG의 <title>·<desc> 포함 - 읽기 도구가 읽는 글)."""
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", strip_style(doc))))


def assert_no_provenance(doc: str) -> None:
    body = strip_style(doc)
    for cls in OLD_CLASSES:
        assert not re.search(r'class="[^"]*\b%s\b[^"]*"' % re.escape(cls), body), f"class {cls}"
    assert "<script" not in body.lower() and "onload=" not in body.lower()
    text = visible_text(doc)
    for s in OLD_STRINGS:
        assert s not in text, f"출처 표시 문구 남음: {s}"
    left = [m.group(0) for m in re.finditer(r".{0,6}집계.{0,6}", text)]
    assert all("집계 단위" in x for x in left), left      # 참고 섹션의 '집계 단위' 설명만 남는다
    for pat in FACT_ID_PATTERNS:
        m = re.search(pat, text)
        assert not m, f"사실 번호 노출: {m.group(0)}"
