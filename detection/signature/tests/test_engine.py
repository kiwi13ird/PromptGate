"""signature.engine 계약 테스트 - 인식기가 아직 없는 상태의 뼈대 동작과, 인식기를 꽂았을 때의 계약."""

from __future__ import annotations

import pytest

from signature import engine


class _FakeRecognizer:
    """계약(Recognizer 프로토콜)을 만족하는 최소 인식기 - 고정 문자열을 찾는다."""

    def __init__(self, entity_type: str, needle: str, score: float = 0.9):
        self.entity_type = entity_type
        self._needle = needle
        self._score = score

    def analyze(self, text: str) -> list[engine.Hit]:
        hits = []
        start = text.find(self._needle)
        while start != -1:
            hits.append(engine.Hit(self.entity_type, start, start + len(self._needle), self._score))
            start = text.find(self._needle, start + 1)
        return hits


def test_no_recognizers_means_no_hits():
    assert engine.RECOGNIZERS == ()
    assert engine.query("주민등록번호 990314-1234567") == []
    assert engine.counts([]) == {}


def test_hits_are_sorted_and_counted(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        engine,
        "RECOGNIZERS",
        (_FakeRecognizer("KR_PHONE_NUMBER", "010-1234-5678"), _FakeRecognizer("KR_RRN", "990314-1234567")),
    )
    text = "주민 990314-1234567 전화 010-1234-5678 다시 010-1234-5678"
    hits = engine.query(text)
    assert [h.entity_type for h in hits] == ["KR_RRN", "KR_PHONE_NUMBER", "KR_PHONE_NUMBER"]
    assert hits[0].start == text.index("990314") and hits[0].end == hits[0].start + 14
    assert engine.counts(hits) == {"KR_RRN": 1, "KR_PHONE_NUMBER": 2}


def test_hit_is_value_only_no_text():
    hit = engine.Hit("KR_RRN", 3, 17, 0.95)
    assert set(vars(hit)) == {"entity_type", "start", "end", "score"}  # 매치 문자열 필드가 없어야 한다
