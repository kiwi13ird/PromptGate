# windowhash — 창 해시 탐지

기밀문서의 **모든 위치**에서 30자(한글·영문·숫자만 센 길이) 창을 그대로 해시해 저장하고, 입력도 같은 창으로
해시해 하나라도 정확히 일치하면 차단한다. `hashdb`(MinHash+LSH, Winnowing)를 대체한다.
근거: `docs/reports/verbatim-miss-diagnosis-2026-09-10.md` §9~§12.

## 규칙 (전부)

1. **압축**: 한글·영문·숫자만 남긴다(`hashing.compact`). 공백·구두점·표 구분자·불릿은 버린다.
2. **창 해시**: 압축 열의 모든 위치에서 길이 `WINDOW`(30)의 롤링 해시(`hashing.window_hashes`). 고르지 않는다.
3. **식별력 규칙**: 2개 이상 문서에 있는 창은 근거가 아니다(`engine.UNIQUE_DOC_CUT`).
4. **판정**: 남은 창이 하나라도 있으면 차단. `score`는 일치 창 비율(0~1, 정보용, 근거가 나온 뒤는 50개마다 1개 표본). 근거 = 일치 창이 가장 많은 문서, 위치 = 그 창들의 원문 구간(같은 창이 문서 여러 곳에 있으면 입력 길이보다 멀리 떨어진 위치는 다른 덩어리로 보고 가장 많이 몰린 덩어리).

보장: 압축 후 30자 이상 그대로 겹치면 반드시 잡힌다. 하한: 압축 후 30자 미만(원문 약 40자)은 창이 없어 검사 불가.

## 파일

| 파일 | 역할 |
|---|---|
| `hashing.py` | 압축, 창 해시, 원문 오프셋 복원. 파라미터 `WINDOW` |
| `index.py` | Redis 역색인 `wh:{hash}` → `{doc_id:start:end}`, `wh:docs` |
| `store.py` | SQLite 원장 `documents`, `windows`(재적재·삭제·복구용) |
| `engine.py` | ingest / clear / query / reason |
| `detect.py` | `ENGINES`, `query_text`, `decide`, `Decision` (detection_service가 쓰는 계약). detection_service는 ① 이 판정 → 차단이면 즉시 응답, 통과면 ② signature 패턴매칭 순서로 돈다 |
| `ingest.py`, `cli.py` | 적재 배치: `python -m windowhash.cli ingest <디렉터리> --db … --redis-…` |
| `signal.py` | `HashSignal` (Presidio 필드명, hashdb와 동일) |

## 실측 (테스트베드 20종, 창 30, fakeredis)

원문 산문·표 100~2,000자 전부 30/30 · 문장 단위 편집 13종 24/26칸 30/30 · 표 구분자(탭·공백·줄바꿈) 30/30 ·
무관 산문 251조각 오탐 0 · 가짜 표 120건 오탐 0 · 문서 전체 20/20(5.3만자 75 ms) · 창 206,950개.

## 못 잡는 것

단어 단위로 다시 쓴 글(30자마다 편집), 값을 전부 바꾼 표. 해시가 아니라 의미 유사도 계층의 몫.

## 전환 상태

1. ✅ `detection_service`(main·pipeline·schemas)와 Gateway addon 테스트가 windowhash만 import (2026-09-10, 전체 243 tests). 실행 경로 어디에도 hashdb import 없음. Redis 키(`wh:`)·SQLite 파일(`windowhash.sqlite3`)도 옛 엔진(`wn:`/`lsh:`, `hashdb.sqlite3`)과 분리.
2. 서버: `src` 복사 → Redis db1 비우기 → `python -m windowhash.cli ingest /opt/detection/corpus …` → uvicorn 재시작 (승인 후)
3. `hashdb` 제거, ADR-0007(MinHash 확정) 재오픈 기록
