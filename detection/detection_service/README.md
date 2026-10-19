# detection_service

`hashdb`를 HTTP로 노출하는 FastAPI 래퍼. `gateway-detection-integration-design.md` §4 계약의
서버 쪽 구현이다 — Gateway EC2와 Detection EC2가 물리적으로 분리된 별개 인스턴스라 이 홉이
실제로 존재한다(같은 문서 §0).

## 실행

```bash
cd src
export REDIS_HOST=127.0.0.1   # 전부 기본값(127.0.0.1:6379 db1)이면 생략 가능
export REDIS_PASSWORD=...     # runbook §5의 requirepass와 맞출 것
uvicorn detection_service.main:app --host 0.0.0.0 --port 8000
```

SQLite(`HASHDB_PATH`)는 이 서비스가 더 이상 안 쓴다 — 실시간 조회는 Redis만 본다. 적재
(SQLite+Redis 양쪽에 씀)는 `hashdb.cli ingest`가 별도로 담당한다.

`--host 0.0.0.0`이 필요하다 — `127.0.0.1`로 바인딩하면 Gateway EC2의 Security Group을
아무리 열어도 다른 인스턴스에서 접근할 수 없다(`detection-subnet-ec2-redis-runbook.md` §6
트러블슈팅 항목과 동일한 함정).

## API

- `GET /health` → `{"status": "ok"}`
- `POST /detect` → `hashdb.detect.query_text()` + `decide()`를 그대로 실행하고
  `Decision`을 JSON으로 직렬화. 요청/응답 스키마는 `schemas.py` 참고.

`query_text()`가 MinHash와 Winnowing 두 엔진을 같이 돌리므로(`hashdb/README.md`), 응답의
`evidence`에는 어느 엔진의 어떤 지표로 판정했는지가 실린다:

```json
{"blocked": true, "reason": "...",
 "evidence": {"doc_id": "15_NDA_초안", "score": 1.0, "chunk_span": "184-282",
              "detector": "Winnowing", "score_kind": "containment"}}
```

`detector`는 `"MinHash"`(`score_kind: "jaccard"`, 차단 기준 0.90) 또는 `"Winnowing"`
(`score_kind: "containment"`, 차단 기준 0.5). 같은 `score` 값이라도 엔진에 따라 의미가 다르므로
로그를 볼 때 이 두 필드를 같이 봐야 한다. Gateway 쪽 `detection_client.py`는 `evidence`를 dict
그대로 넘기므로 이 필드 추가로 바뀔 게 없다.

## 알려진 제한사항

- Redis 커넥션을 앱 시작 시 1회 열고 재사용한다 — 이 API가 읽기 전용이라 안전하다. 적재
  (쓰기)는 CI/CD 배치 그룹(`hashdb.cli ingest`)만 한다는 전제가 깨지면 이 가정도 다시 봐야
  한다.
- Redis 장애 시 SQLite로 폴백하지 않는다(의도된 설계, `hashdb/README.md` 참고) — Redis가
  죽으면 이 서비스는 신호 없음을 돌려준다. 호출자(Gateway)가 이걸 degraded로 인지해야 한다.

## 테스트

```bash
cd src && python -m pytest detection_service/tests/ -q
```

## 처리 순서 (2026-09-04, `pipeline.py`)

```
POST /detect ─▶ 전처리(normalize_text · detect_lang) ─┬─▶ hashdb.detect.query_text ─▶ blocked / reason / evidence
                                                       └─▶ signature.engine.query  ─▶ signals
                                                                                      detectors: {"hashdb": "ok"|"error", "signature": "ok"|"error"}
```

- 같은 전처리 텍스트를 두 판정기에 `ThreadPoolExecutor`로 동시에 넘긴다. 결과는 **합치지 않고** 나란히 싣는다 —
  `blocked`는 해시 판정만 반영하고, PII 적중(`signals`, entity_type/start/end/score)은 그 옆에 붙는다.
- 두 판정기는 격리된다. 한쪽 예외는 `detectors`에 "error"로만 표시되고 다른 쪽 결과는 정상.
- `signature.engine`은 계약과 뼈대만 있다(`RECOGNIZERS = ()`). 인식기는 다른 팀원이 붙인다 —
  `docs/handoff/signature-engine-contract.md`.
