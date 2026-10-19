# 로컬 대시보드 확인 구성 (2026-10-06)

수정한 화면(문서별 키워드 · 리포트 · GPU 상태)을 운영과 분리해 눌러 보는 구성. **운영 서버·DB에 연결하지 않음.**

## 켜기
`kisia/project` 폴더에서:

```bash
node local-dashboard/start-all.mjs
```

- 접속 http://localhost:5173 · 계정은 `local-test-account.json` (이 구성에서만 쓰는 시험 값)
- 끄기: 그 창에서 Ctrl+C
- 처음 한 번은 `dashboard-frontend-final`에서 `npm ci`와 `.env.production.local`(= `.env.example` 복사)이 필요 — 2026-10-06에 이미 해 둠

## 구성
| 서버 | 주소 | 파일 |
|---|---|---|
| 화면 개발 서버 | 5173 | `../dashboard-frontend-final` (수정본) |
| 대시보드 백엔드 | 9100 | `run-backend.mjs` + `server/` (운영 10/4본 + GPU 경로, 보호 문서 5건 예시) |
| 가짜 Detection | 18000 | `fake-detection.mjs` + `live/` (운영 응답 모양, 메모리 상태) |

## 보안 이벤트 원문 보기 예시
- 켜면 예시 이벤트 5건이 들어감(`sample-events.mjs`, 가상 회사 문서 `samples/` + 가짜 개인정보): 해시 차단 2(그대로 복사·일부 수정) · 마스킹 1 · 패턴 차단 1 · 허용 1
- 로컬 백엔드는 `EVIDENCE_SHOW_RAW=1`로 개인정보 가림을 끄고 원문 그대로 보여 줌(운영 기본값은 가림)

## 상황 바꿔 보기
- 추출: GPU가 연결된 상태에서 "추출 요청" → 대기 2초 → 추출 중 5초 → 완료 + 문서별 후보 2개가 승인 대기로 추가(가상 회사 표현)
- GPU 끊김 켜기/끄기: `curl -X POST http://127.0.0.1:18000/fake/gpu` (즉시 켜짐↔꺼짐)
- GPU 켜기·끄기 버튼(10/7): 켜기 → 켜는 중 4초 → 모델 준비 중 6초 → 연결됨 · 끄기 → 끄는 중 5초 → 꺼짐 · 리포트 생성·추출 실행 중 끄기는 409(운영과 같은 규칙)
- 탐지 반영 실패 켜기/끄기: `curl -X POST http://127.0.0.1:18000/fake/reload-fail`
