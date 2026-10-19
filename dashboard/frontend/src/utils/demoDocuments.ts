// 시연 문서(2026-10-16 공통 규칙 docs/handoff/stats-rules-2026-10-16/SPEC.md 2.2): 문서 번호가 DEMO_로 시작.
// '등록 문서 n개'·'n / n개 문서 보호 중' 같은 문서 수에서 뺀다. 목록에는 그대로 보이고 '시연 · 통계 제외' 표시만 붙는다.
// 이 문서만 일치한 이벤트는 대시보드 서버가 시험 기록처럼 통계·목록 기본 보기에서 뺀다(test-events.mjs isDemoDocumentEvent)
export const DEMO_DOC_PREFIX = 'DEMO_';

export const isDemoDocument = (documentId: string | null | undefined) => String(documentId ?? '').startsWith(DEMO_DOC_PREFIX);
