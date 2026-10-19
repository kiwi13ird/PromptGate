# Security Gateway — Frontend 개발 전달본

2026-10-06에 운영 배포 및 검수한 최신 승인 프런트엔드 기준입니다. UI·라우팅·CSS·API service/adapter·정적 폰트 소스는 승인본과 동일합니다. 운영 서버나 설정은 이 패키지 생성 과정에서 변경하지 않았습니다.

이 패키지는 **프런트엔드만** 포함합니다. Backend, DB, Gateway, Detection, 운영 로그인 정보와 환경 파일은 포함하지 않습니다. 백엔드 없이 개발 서버를 띄울 수는 있지만 로그인·실제 데이터 조회는 동작하지 않습니다. 팀의 승인된 개발 백엔드를 연결하세요. API 오류를 fixture로 숨기지 마세요.

## 1. 설치

Node.js 22.13 이상이 필요합니다. Vite native config loader를 지원하는 Node 22 LTS의 최신 패치 버전을 권장합니다. 압축을 푼 뒤 `dashboard-frontend-final` 폴더에서 실행합니다.

```bash
npm install
```

버전 고정을 엄격히 유지하려면 `npm ci`를 사용할 수 있습니다. 전달본의 의존성 목록과 lockfile은 승인본을 유지했습니다. `pg` 등 기존 의존성이 남아 있어도 백엔드 구현이나 DB 연결 정보는 제공하지 않습니다.

## 2. 환경 설정 및 개발 서버

`.env.example`을 `.env.production.local`로 복사합니다. npm 개발 명령도 real API를 보장하기 위해 production **mode**를 사용합니다. 이는 Vite 개발 서버 실행이며 운영 배포가 아닙니다.

```bash
# macOS / Linux
cp .env.example .env.production.local
```

```powershell
# Windows PowerShell
Copy-Item .env.example .env.production.local
```

`VITE_DEV_PROXY_TARGET`을 팀의 로컬/개발 백엔드 origin으로 설정합니다. 기본 템플릿은 `http://127.0.0.1:9100`입니다. 프런트엔드는 `/api/...`를 요청하고 개발 서버가 이를 프록시합니다. `VITE_API_BASE_URL=/`는 유지하세요. 운영 API에 자동 연결하지 않습니다.

```bash
npm run dev
```

터미널에 표시되는 로컬 주소로 접속하세요. `npm run dev:real`도 같습니다. 인증은 기존 API의 cookie 기반 세션 방식입니다. 계정은 팀의 개발 환경 절차로 별도 발급받으세요. 인증 실패/CORS/cookie 문제를 mock 로그인으로 우회하지 마세요. 호스트·Secure cookie·백엔드 허용 origin 설정은 개발 백엔드 담당자와 확인해야 합니다.

`VITE_*` 값은 브라우저 번들에 노출될 수 있습니다. 비밀번호, API key, token, DB 연결 문자열을 넣지 마세요. `.env.production.local`은 커밋/공유하지 않습니다.

## 3. Production build / 로컬 검증

```bash
npm run typecheck
npm test
npm run build
npm run verify:real-artifact
npm run preview
```

`npm run build`와 `npm run build:real`은 동일하며 `dist-real/`을 생성합니다. 원래 운영 빌드 설정인 `vite.config.ts`를 사용합니다. 개발 프록시는 `vite.local.config.ts`에만 있으며 production build/preview에는 적용되지 않습니다. preview에서 API를 사용하려면 별도 같은 origin의 `/api` reverse proxy 또는 적절히 허용된 개발 API 설정이 필요합니다. 정적 호스팅에는 SPA history fallback 및 기존 `/api` reverse proxy가 필요합니다. 빌드 명령은 배포하지 않습니다.

`verify:real-artifact`는 HTTP/auth real adapter 포함 여부와 mock/test module 미포함, 출력 해시를 확인합니다. 단위 테스트는 `vitest.config.ts`의 test-only env와 mock alias를 사용하며 실제 API를 호출하지 않습니다.

## 4. 주요 route

| Route | 화면 / 구현 |
| --- | --- |
| `/`, `/dashboard` | 인증 상태별 진입 / Overview 리다이렉트 |
| `/login` | `src/pages/LoginPage.tsx` |
| `/overview` | `src/pages/OverviewPage.tsx` |
| `/events` | `src/pages/SecurityEventsPage.tsx` |
| `/events/:eventId` | `src/pages/EventDetailPage.tsx` |
| `/requests/:requestId` | `src/pages/RequestReviewPage.tsx` |
| `/documents` | `src/pages/ProtectedDocumentsPage.tsx` |
| `/documents/:documentId` | `src/pages/ProtectedDocumentDetailPage.tsx` |
| `/policies` | `src/pages/PolicyManagementPage.tsx` |
| `/traffic` | `src/pages/TrafficPerformancePage.tsx` — 측정 비교 포함 |
| `/audit-logs` | `src/pages/AuditLogsPage.tsx` |

등록 지점은 `src/App.tsx`입니다. Performance는 별도 `/performance` route가 아니라 Traffic의 기존 측정/비교 영역입니다.

## 5. API / Service / Adapter

- `src/api/endpoints.ts`: API 경로 목록
- `src/api/httpClient.ts`: fetch, timeout, cookie, 공통 오류 처리
- `src/api/httpAdapter.ts`, `gatewayApi.ts`: real API 구현 / interface
- `src/api/dto.ts`, `schemas.ts`, `mappers.ts`: 응답 DTO / Zod 검증 / 화면 모델 매핑
- `src/services/`: events, documents, policies, traffic, audit 등 화면용 service
- `src/auth/realAuthAdapter.ts`, `src/services/authService.ts`, `src/hooks/useAuth.tsx`: 인증
- `src/queries/keys.ts`: React Query 캐시 키
- `src/config/buildMode.ts`, `env.ts`, `vite.config.ts`: real adapter 선택 / 환경 검사

리포트/키워드 API는 아직 이 패키지에 구현되어 있지 않습니다. 새 endpoint 계약은 담당자와 합의하고 DTO → schema → mapper → adapter/service → query → page 순으로 연결하세요. 미리 없는 endpoint나 응답 필드를 가정해 표시하지 마세요. 원본 본문과 민감정보는 기존 API 권한·보호 규칙을 유지해야 합니다.

## 6. 공통 Layout / Component

- `src/components/AppLayout.tsx`: Sidebar / Topbar / route workspace
- `src/components/common.tsx`: 공통 page/section/상태 표현
- `components/ui/`: button, input, dialog, table, toast 등 기반 UI
- `src/components/EventsTable.tsx`, `AutoRefreshBar.tsx`: 표 / 자동 갱신
- `src/components/EvidenceDocumentViewer.tsx`, `EventEvidencePanel.tsx`: 본문 비교 / 근거 표시
- `lib/utils.ts`: 공통 보조 함수

## 7. CSS / Design System / Font

`src/main.tsx`에 아래 CSS가 순서대로 로드됩니다. 뒤 파일의 override를 확인하고 기존 순서를 유지하세요.

1. `src/styles.css`: 기본 스타일 / Tailwind
2. `src/design-system.css`: 공통 디자인 토큰
3. `src/console-system.css`: Console 공통 구조
4. `src/workbench-v3.css`: V3 정보 구조와 화면 스타일
5. `src/workbench-v31.css`: 결과 / Evidence 시각 계층
6. `src/product-polish.css`: 최종 typography / surface 정돈

Pretendard는 `src/assets/fonts/PretendardVariable.woff2`에 로컬 포함됩니다. 폰트 라이선스도 포함했습니다. 결과 색은 BLOCK red / MASK amber / ALLOW green, 링크는 blue입니다. 새 화면에서도 fake severity/risk/health, 불필요한 KPI/card나 별도 브랜드를 추가하지 마세요.

## 8. 리포트 / 키워드 화면 개발 참고

- `AuditLogsPage.tsx`: 목록, 조건 필터, 빈 결과와 오류, pagination — 리포트 이력 화면
- `SecurityEventsPage.tsx` + `EventsTable.tsx`: 조회 조건 / URL 상태 / compact table / 상세 연결
- `PolicyManagementPage.tsx`: 편집 dialog / 입력 검증 / 상태 변경 / version 이력 — 키워드 관리
- `ProtectedDocumentsPage.tsx`: 자산 목록 / 검색 / 관리 상태
- `EventDetailPage.tsx`: 실제 근거와 정책 판단을 우선하는 상세 화면
- `PerformanceRunsPanel.tsx`: 기존 데이터의 비교 / 누락값 처리

새 route는 `src/App.tsx`, 메뉴/제목 매핑은 `AppLayout.tsx`에 연결합니다. 기존 navigation wrapper, query key, 권한과 오류 처리 패턴을 재사용하세요. 관리 write 기능은 개발 환경에서만 검증하고 운영에서 자동 실행하지 마세요.

## 9. 실제 데이터 원칙 / 전달 범위

**runtime과 production build에는 실제 API 데이터만 사용합니다. fixture는 단위 테스트에서만 사용합니다.** `src/mocks`, mock adapter와 `*.test.*`는 기존 테스트 소스이며 production bundle에서 제외됩니다. mock 로그인 상수는 가상 테스트용이고 운영 계정이 아닙니다. runtime API 실패 시 fixture/임의 수치로 대체하지 않습니다. 누락된 데이터는 누락으로 표현합니다.

포함: `src`, `public`, `components`, `lib`, 폰트/라이선스, 실행 설정, npm manifest/lockfile, 단위 테스트, real artifact 검증 명령.

제외: 실제 `.env`, Backend, 운영 자료/백업, credential/key, 세션 값, HAR, node_modules, dist/build, 로그, 캡처/영상, 임시 검수 산출물.

전달 편의상 npm scripts에서 포함하지 않은 backend/demo/e2e/운영 명령을 제거하고 개발용 프록시 config와 test-only env를 추가했습니다. production UI·API·라우팅·CSS 소스와 의존성/lockfile은 변경하지 않았습니다. 운영 배포본 `index.html`의 기준 SHA256은 `c690d12b60bede94898a9d90bae635dfbce548f003955b9d5b2eadb2c450bc93`입니다.
