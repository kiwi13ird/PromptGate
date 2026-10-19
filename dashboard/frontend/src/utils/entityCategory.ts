// 탐지 유형 → 분류 (서버 entityCategory와 같은 기준, 2026-10-10)
// 자격증명: Detection signature_rules(CREDENTIAL) + 리포트 기준, 기밀 키워드: DOC_KEYWORD, 나머지는 개인정보
export type EntityCategory = 'PII' | 'CREDENTIAL' | 'KEYWORD';

const CREDENTIAL_TYPES = new Set(['GENERIC_API_KEY', 'GITHUB_TOKEN', 'PASSWORD', 'AWS_ACCESS_KEY', 'PRIVATE_KEY']);

export const entityCategory = (type: string): EntityCategory =>
  type === 'DOC_KEYWORD' ? 'KEYWORD' : CREDENTIAL_TYPES.has(type) ? 'CREDENTIAL' : 'PII';

export const categoryTitle: Record<EntityCategory, string> = { PII: '개인정보', CREDENTIAL: '자격증명', KEYWORD: '기밀 키워드' };

// 패턴 검사 결과 이름: 기밀 키워드만이면 '기밀 키워드', 다른 유형과 섞이면 '민감정보·기밀 키워드', 아니면 '민감정보 패턴'
export function signatureLabel(entityTypes: string[]) {
  const keyword = entityTypes.includes('DOC_KEYWORD');
  const other = entityTypes.some(type => type !== 'DOC_KEYWORD');
  return keyword && !other ? '기밀 키워드' : keyword ? '민감정보·기밀 키워드' : '민감정보 패턴';
}
