"""PII 시그니처 판정기 패키지.

`engine.py`가 외부에 보이는 유일한 계약이다. `detection_service.pipeline`은 `engine.query()`,
`engine.blocking()`, `engine.reason()`, `engine.NAME`만 부른다 - 인식기를 어떻게 구현하든 그
네 개만 지키면 파이프라인은 손대지 않아도 된다(`docs/handoff/signature-engine-contract.md`).
"""
