"""입력을 색인과 대조해 차단/통과를 판정한다. hashdb/detect.py의 엔진 규약과 Decision을 그대로 가져와
엔진을 하나로 줄였다. detection_service는 `query_text()`·`decide()`·`Decision`만 쓴다.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType

import redis

from . import engine
from .signal import HashSignal

__all__ = ["ENGINES", "ENTITY_TYPE", "Decision", "HashSignal", "decide", "query_text"]

ENGINES: tuple[ModuleType, ...] = (engine,)
ENTITY_TYPE = engine.ENTITY_TYPE
_ENGINE_BY_NAME = {e.NAME: e for e in ENGINES}


def query_text(r: redis.Redis, text: str) -> list[HashSignal]:
    """정규화된 텍스트 하나를 대조하고 신호를 근거(일치 창 수) 내림차순으로 돌려준다."""
    signals: list[HashSignal] = []
    for e in ENGINES:
        signals.extend(e.query(r, text))
    signals.sort(key=lambda s: (-s.x_score_raw, -s.score))  # 근거의 양(고유 창 수)이 먼저
    return signals


@dataclass
class Decision:
    """차단/통과 둘뿐. `signal`은 근거 신호(통과면 None)."""

    blocked: bool
    reason: str
    signal: HashSignal | None = None


def decide(signals: list[HashSignal]) -> Decision:
    if not signals:
        return Decision(blocked=False, reason="매치 없음")
    top = signals[0]
    e = _ENGINE_BY_NAME[top.x_detector]
    if top.score >= e.BLOCK_THRESHOLD:
        return Decision(blocked=True, reason=e.reason(top, blocked=True), signal=top)
    return Decision(blocked=False, reason=e.reason(top, blocked=False), signal=top)
