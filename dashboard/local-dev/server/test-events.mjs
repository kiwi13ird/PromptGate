// 시험·데모 이벤트 구분 (2026-10-10 결정: 지우지 않고 통계·목록에서만 뺀다)
// 클라이언트 ID 앞부분으로 구분한다. 접두어는 영문·숫자·밑줄만 받는다(SQL 정규식에 그대로 넣기 때문)
export const TEST_CLIENT_PREFIXES = Object.freeze(
  (process.env.TEST_CLIENT_PREFIXES ?? 'demo,evidence,codex,diag,gateway')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => /^[A-Za-z0-9_]+$/.test(value)),
);

export function isTestEvent(event) {
  const clientId = String(event?.client_id ?? '');
  return TEST_CLIENT_PREFIXES.some((prefix) => clientId === prefix || clientId.startsWith(`${prefix}-`));
}

// 같은 기준을 SQL(client_id !~ 정규식)에서 쓸 때. 접두어가 없으면 아무것도 맞지 않는 식
export const TEST_CLIENT_PATTERN = TEST_CLIENT_PREFIXES.length ? `^(${TEST_CLIENT_PREFIXES.join('|')})(-|$)` : '$^';
