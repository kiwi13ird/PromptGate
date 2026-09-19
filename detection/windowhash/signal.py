"""탐지 신호 - 엔진이 내놓는 결과 형식. hashdb/signal.py에서 그대로 가져왔다(decisions.md ⑩, Presidio 필드명).

detection_service가 이 필드명(x_evidence, x_chunk_span, x_detector, x_score_kind)으로 응답을 만들므로
이름을 바꾸지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MatchSpan:
    """입력의 한 구간이 문서의 한 구간과 그대로 겹친 덩어리 하나. 판정 로그에 실린다(원문 없음)."""

    in_start: int
    in_end: int
    doc_start: int
    doc_end: int
    windows: int  # 이 덩어리의 고유 일치 창 수


@dataclass
class HashSignal:
    """"입력의 이 구간이 이 문서의 이 구간과 그대로 겹친다"는 신호 하나.

    entity_type   신호 종류(엔진의 ENTITY_TYPE)
    start, end    입력 쪽 구간(정규화 텍스트 오프셋). 가장 큰 덩어리의 첫 창 시작 ~ 마지막 창 끝
    score         입력 덮임 비율(0~1): 조회한 입력 창 중 이 문서와 일치한 창의 비율. 근거가 나온 뒤는 표본(50개마다 1개)으로 추정. 정보용, 판정은 창 존재 여부
    x_score_raw   가장 큰 덩어리의 고유 일치 창 수(근거의 양)
    x_score_kind  "coverage"
    x_detector    엔진 이름
    x_evidence    겹친 문서의 doc_id
    x_chunk_span  가장 큰 덩어리의 문서 쪽 구간 "start-end"
    x_examined    조회한 입력 창 수(표본 포함) - score의 분모
    x_spans       덩어리 목록(큰 순, 최대 3개). 입력 두 곳이 문서 두 곳과 겹치면 둘 다 여기 있다
    """

    entity_type: str
    start: int
    end: int
    score: float
    x_score_raw: float
    x_score_kind: str = "coverage"
    x_detector: str = "WindowHash"
    x_evidence: str = ""
    x_source: str = "windowhash"
    x_chunk_span: str = ""
    x_examined: int = 0
    x_spans: tuple[MatchSpan, ...] = field(default_factory=tuple)
