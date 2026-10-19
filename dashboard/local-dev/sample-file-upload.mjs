// 로컬 확인용: ChatGPT에 파일을 올리고 질문을 따로 보낸 한 번의 대화 (2026-10-09).
// 파일 이벤트(파일 번호) + 질문 이벤트(첨부 번호) + 판정 기록(파일 전체 1행 + 칸별 행). 값은 모두 가상이다.
const FILE_REF = '00000000ddcc81fa9d8d70a1644600aa';
const RRN = '900315-2123456';
const minutesAgo = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();

// 칸: [칸 번호, 원문, 본문 순번, 가린 값들[[값, 유형]]]
const CELLS = [
  ['docx:header0:p0', '네오웍스 경영지원실 · 대외비', undefined, []],
  ['docx:body:p0', '신규 입사자 인사 및 급여 등록 요청서', 0, []],
  ['docx:body:p1', '인사급여 관리 시스템에 아래 입사자의 인사정보와 급여 지급 정보를 등록합니다.', 1, []],
  ['docx:body:t0:r0:c0:p0', '문서번호', 2, []], ['docx:body:t0:r0:c1:p0', '작성일', 2, []], ['docx:body:t0:r0:c2:p0', '처리 구분', 2, []],
  ['docx:body:t0:r1:c0:p0', 'NW-HR-261009-01', 2, []], ['docx:body:t0:r1:c1:p0', '2026-10-09', 2, []], ['docx:body:t0:r1:c2:p0', '등록 요청', 2, []],
  ['docx:body:p3', '김하늘 인사정보', 4, []],
  ['docx:body:t1:r0:c0:p0', '항목', 5, []], ['docx:body:t1:r0:c1:p0', '요청 내용', 5, []],
  ['docx:body:t1:r1:c0:p0', '주민등록번호', 5, []], ['docx:body:t1:r1:c1:p0', RRN, 5, [[RRN, 'KR_RRN']]],
  ['docx:body:t1:r2:c0:p0', '이메일', 5, []], ['docx:body:t1:r2:c1:p0', 'haneul.kim@example.com', 5, [['haneul.kim@example.com', 'EMAIL_ADDRESS']]],
  ['docx:body:t1:r3:c0:p0', '휴대전화', 5, []], ['docx:body:t1:r3:c1:p0', '010-2468-1357', 5, [['010-2468-1357', 'KR_PHONE_NUMBER']]],
  ['docx:body:t1:r4:c0:p0', '급여 계좌', 5, []], ['docx:body:t1:r4:c1:p0', '110-245-678901', 5, [['110-245-678901', 'KR_BANK_ACCOUNT']]],
  ['docx:body:t1:r5:c0:p0', '비고', 5, []], ['docx:body:t1:r5:c1:p0', '연락은 업무 메일 haneul.kim@example.com 으로만', 5, [['haneul.kim@example.com', 'EMAIL_ADDRESS']]],
  ['docx:body:p5', '위 내용으로 등록 부탁드립니다.', 7, []],
  ['docx:footer0:p0', '가상 기업 테스트 문서 · 실제 개인정보 아님', undefined, []],
];

function segmentRow(requestId, [id, text, order, masks], ts) {
  const findings = masks.map(([value, type]) => {
    const start = Array.from(text.slice(0, text.indexOf(value))).length;
    return { entity_type: type, start, end: start + Array.from(value).length, replacement: `[${type}]`, policy_action: 'mask_full' };
  });
  let masked = text;
  for (const [value, type] of masks) masked = masked.replace(value, `[${type}]`);
  return {
    request_id: `${requestId}#f:0:${id}`, ts, prompt: text, prompt_kept: true, block_order: order,
    decided_by: masks.length ? 'signature' : 'none', pii_hits: masks.length ? masks.map(([, type]) => `${type}:1`).join(',') : undefined,
    masked_text: masks.length ? masked : undefined, findings: masks.length ? findings : undefined,
  };
}

export function buildFileSamples() {
  const fileRequest = 'req-local-file-upload';
  const promptRequest = 'req-local-file-question';
  const fileAt = minutesAgo(3);
  const promptAt = minutesAgo(2.5);
  const whole = CELLS.map(([, text]) => text).join('\n');
  const file = {
    event: { eventId: 'evt-local-file-upload', requestId: fileRequest, timestamp: fileAt, clientId: 'chrome-local-demo', targetLlm: 'ChatGPT',
      contentType: 'file', host: 'sdmntprkoreacentral.oaiusercontent.com', endpoint: '/files/00000000-ddcc-81fa-9d8d-70a1644600aa/raw',
      detectionOutcome: 'MATCH', finalAction: 'MASK', enforcement: { applied: true }, reasonCode: 'pii', fileId: FILE_REF,
      detections: [{ detector: 'SIGNATURE', matchType: 'SIGNATURE_RULE', action: 'MASK', entityCounts: [
        { entityType: 'EMAIL_ADDRESS', count: 2 }, { entityType: 'KR_BANK_ACCOUNT', count: 1 }, { entityType: 'KR_PHONE_NUMBER', count: 1 }, { entityType: 'KR_RRN', count: 1 }] }] },
    decision: { request_id: fileRequest, ts: fileAt, decided_by: 'signature', prompt: whole, prompt_kept: true, prompt_chars: Array.from(whole).length,
      text_chars: Array.from(whole).length, content_type: 'file', filename: '신규입사자_인사급여_등록요청서.docx', total_ms: 12.3, hash_status: 'ok', signature_status: 'ok',
      reason: '패턴 적중: EMAIL_ADDRESS:2,KR_BANK_ACCOUNT:1,KR_PHONE_NUMBER:1,KR_RRN:1' },
    segments: CELLS.map((cell) => segmentRow(fileRequest, cell, fileAt)),
  };
  const prompt = {
    event: { eventId: 'evt-local-file-question', requestId: promptRequest, timestamp: promptAt, clientId: 'chrome-local-demo', targetLlm: 'ChatGPT',
      contentType: 'prompt', host: 'chatgpt.com', endpoint: '/backend-api/f/conversation', detectionOutcome: 'NO_MATCH', finalAction: 'ALLOW',
      detections: [], attachedFileIds: [FILE_REF] },
    decision: { request_id: promptRequest, ts: promptAt, decided_by: 'none', prompt: '이 파일 내용을 표로 정리해줘', prompt_kept: true, prompt_chars: 15,
      text_chars: 15, content_type: 'prompt', total_ms: 3.1, hash_status: 'ok', signature_status: 'ok', reason: '일치 없음' },
  };
  return [file, prompt];
}
