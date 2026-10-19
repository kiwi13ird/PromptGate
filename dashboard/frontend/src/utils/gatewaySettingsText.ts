import type { GatewaySettingsValues } from '@/src/api/gatewaySettingsSchemas';

// Gateway 처리 설정 화면·감사 요약에 쓰는 이름표. 값(코드)은 바꾸지 않고 보여 주는 글자만 정한다.
export const TIMEOUT_ACTION_TEXT = { forward: '원본 전송', block: '차단' } as const;
export const UNINSPECTABLE_ACTION_TEXT = { allow: '허용', block: '차단' } as const;

const FIELD_TEXT: Record<string, string> = {
  timeout: '검사 지연 설정',
  'timeout.prompt': '질문 지연 설정',
  'timeout.prompt.action': '질문 지연 시 처리',
  'timeout.prompt.seconds': '질문 대기 시간',
  'timeout.file': '파일 지연 설정',
  'timeout.file.action': '파일 지연 시 처리',
  'timeout.file.seconds': '파일 대기 시간',
  uninspectable: '검사할 수 없는 파일 설정',
  'uninspectable.image': '이미지',
  'uninspectable.scanned_pdf': '스캔 PDF',
  'uninspectable.other': '기타 형식',
  notify_on_allow: '허용 알림',
};

/** Gateway가 거부한 칸 경로(timeout.file.seconds 등)의 이름. 모르는 경로는 그대로. */
export function settingsFieldText(field: string): string {
  return FIELD_TEXT[field] ?? field;
}

/** 입력 칸에 넣는 초 표시: 2 → "2.0", 0.5 → "0.5", 0.125 → "0.125" */
export function formatSeconds(seconds: number): string {
  return Number.isInteger(seconds) ? seconds.toFixed(1) : String(seconds);
}

/** 감사 기록 요약 문장(명세 §2.5, 백엔드 summarizeGatewaySettings와 같은 순서·문구). */
export function summarizeGatewaySettings(values: GatewaySettingsValues, isDefault = false): string {
  const parts = [
    `질문 지연 시 ${TIMEOUT_ACTION_TEXT[values.timeout.prompt.action]}(${values.timeout.prompt.seconds}초)`,
    `파일 지연 시 ${TIMEOUT_ACTION_TEXT[values.timeout.file.action]}(${values.timeout.file.seconds}초)`,
    `이미지 ${UNINSPECTABLE_ACTION_TEXT[values.uninspectable.image]}`,
    `스캔 PDF ${UNINSPECTABLE_ACTION_TEXT[values.uninspectable.scanned_pdf]}`,
    `기타 형식 ${UNINSPECTABLE_ACTION_TEXT[values.uninspectable.other]}`,
    `허용 알림 ${values.notify_on_allow ? '켬' : '끔'}`,
  ];
  return `${isDefault ? '기본값 · ' : ''}${parts.join(' · ')}`;
}

/** 두 설정의 달라진 칸(화면 순서). 저장 확인 창의 변경 전·후 목록에 쓴다. */
export function changedSettingsFields(before: GatewaySettingsValues, after: GatewaySettingsValues) {
  const rows: Array<{ field: string; label: string; before: string; after: string }> = [];
  const add = (field: string, from: string, to: string) => { if (from !== to) rows.push({ field, label: settingsFieldText(field), before: from, after: to }); };
  for (const kind of ['prompt', 'file'] as const) {
    add(`timeout.${kind}.action`, TIMEOUT_ACTION_TEXT[before.timeout[kind].action], TIMEOUT_ACTION_TEXT[after.timeout[kind].action]);
    add(`timeout.${kind}.seconds`, `${before.timeout[kind].seconds}초`, `${after.timeout[kind].seconds}초`);
  }
  for (const group of ['image', 'scanned_pdf', 'other'] as const)
    add(`uninspectable.${group}`, UNINSPECTABLE_ACTION_TEXT[before.uninspectable[group]], UNINSPECTABLE_ACTION_TEXT[after.uninspectable[group]]);
  add('notify_on_allow', before.notify_on_allow ? '켬' : '끔', after.notify_on_allow ? '켬' : '끔');
  return rows;
}
