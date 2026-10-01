"""창 해시(window hash) 탐지 - 기밀문서의 모든 위치에서 고정 길이 창을 그대로 해시해 저장하고, 입력도
같은 창으로 해시해 하나라도 정확히 일치하면 차단한다.

2026-09-10 결정으로 `hashdb`(MinHash+LSH → Winnowing 우선)를 대체한다. 근거는
docs/reports/verbatim-miss-diagnosis-2026-09-10.md §9~§11: 문서 20종 규모에서는 지문 선택(Winnowing)이나
확률적 유사도(MinHash)가 정확 일치보다 나은 칸이 하나도 없었고, 그 둘의 복잡성(언어별 k, 대각선, 포함도,
청크 경계)이 곧 놓침과 오탐의 원인이었다.

파이프라인: preprocessing.router.process_input() -> normalized_text
  -> hashing.compact() (한글·영문·숫자만 남김) -> hashing.window_hashes() (모든 위치의 창 해시)
  -> 적재: index(Redis, 조회용) + store(SQLite, 원장)
  -> 조회: index.lookup -> "2개 이상 문서에 있는 창 제외" -> 하나라도 남으면 차단(문서·위치 반환)

파라미터는 창 길이 하나(`hashing.WINDOW`)다.
"""
