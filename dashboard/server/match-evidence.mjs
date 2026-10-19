import { createHash } from 'node:crypto';

// Evidence is a bounded administrator-only preview, never part of event lists.
// Coordinates are Python Unicode code points, not JavaScript UTF-16 offsets.
const TEXT_LIMIT = 2_000_000;
const PREVIEW_CHARS = 320;
export const evidenceTextLimit = TEXT_LIMIT;
export const evidencePageSize = 1800;

// EVIDENCE_SHOW_RAW=1이면 화면용 근거에서 개인정보 가림을 끈다(로컬 확인용). 기본은 지금처럼 가린다.
// 저장 시 가림(validation.mjs의 maskEvidence)은 이 설정과 무관하게 그대로다.
export function evidenceShowsRaw() {
  return process.env.EVIDENCE_SHOW_RAW === '1';
}
function shown(value) {
  return evidenceShowsRaw() ? String(value ?? '') : redactEvidence(value);
}
// 저장된 마스킹 전 미리보기는 가려져 있다. 가림은 글자 수를 그대로 두므로, 판정 기록의 원문을 같은 규칙으로 가린 결과가
// 미리보기와 정확히 같을 때만 그 원문 앞부분으로 되돌린다(같은 입력이라는 확인 없이 다른 원문을 보여 주지 않는다).
// 2026-10-17: 파일 칸 비교·질문 비교(10/9, 10/12)와 같게 EVIDENCE_SHOW_RAW와 무관하게 원문으로 되돌린다(가린 값은 위치 하이라이트로 표시)
function rawBeforePreview(preview, prompt) {
  if (typeof preview !== 'string' || typeof prompt !== 'string') return undefined;
  const length = Array.from(preview).length;
  const head = Array.from(prompt).slice(0, length);
  if (head.length !== length) return undefined;
  // 저장된 미리보기는 Gateway가 가린 탐지 구간까지 █인 경우가 많아 표시용 가림(redactEvidence)만으로는 같지 않다.
  // 그래서 █가 아닌 자리가 모두 원문 앞부분과 같을 때(█는 어떤 글자든 가린 자리) 같은 입력으로 본다.
  const shownChars = Array.from(preview);
  return shownChars.every((char, index) => char === '█' || char === head[index]) ? head.join('') : undefined;
}

// 보호 문서 본문 보기(2026-10-13)의 텍스트 쪽도 이 함수를 그대로 쓴다(같은 1,800자 쪽·같은 가림)
export function documentPage(text, location, request, source) {
  const original = Array.from(text);
  const chars = Array.from(shown(text));
  const start = Math.min(request.offset, Math.max(0, Math.floor((chars.length - 1) / evidencePageSize) * evidencePageSize));
  const end = Math.min(chars.length, start + evidencePageSize);
  const segments = [];
  for (let at = start; at < end; at++) {
    const matched = Boolean(location && at >= location.char_start && at < location.char_end);
    const redacted = chars[at] !== original[at];
    const last = segments.at(-1);
    if (last && last.matched === matched && last.redacted === redacted) last.text += chars[at];
    else segments.push({text:chars[at],matched,redacted});
  }
  return {status:'AVAILABLE',side:request.side,document_id:request.documentId,
    char_start:start,char_end:end,total_chars:chars.length,page_size:evidencePageSize,
    segments,match_location:location,content_source:source};
}

export function redactEvidence(value) {
  return String(value ?? '')
    .replace(/\b(?:Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, (s) => '█'.repeat(Array.from(s).length))
    .replace(/(?:api[_ -]?key|access[_ -]?token|secret|password|비밀번호)\s*[=:]\s*["']?[^\s"',;]+/gi, (s) => '█'.repeat(Array.from(s).length))
    .replace(/\b(?:sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g, (s) => '█'.repeat(Array.from(s).length))
    .replace(/\b\d{6}\s*[-–]?\s*[1-8]\d{6}\b/g, (s) => '█'.repeat(Array.from(s).length))
    .replace(/(?<!\d)(?:\+82[- .]?)?0?1[016789][- .]?\d{3,4}[- .]?\d{4}(?!\d)/g, (s) => '█'.repeat(Array.from(s).length))
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, (s) => '█'.repeat(Array.from(s).length));
}

function span(value, size) {
  if (!value || !Number.isInteger(value.char_start) || !Number.isInteger(value.char_end)
    || value.char_start < 0 || value.char_end <= value.char_start || value.char_end > size) return null;
  return value;
}
function snippets(text, location) {
  const chars = Array.from(shown(text));
  const valid = span(location, chars.length);
  if (!valid) return [];
  const {char_start:start,char_end:end} = valid;
  const positions = [start];
  if (end - start > PREVIEW_CHARS * 2) positions.push(end - PREVIEW_CHARS);
  return positions.map((at) => {
    const stop = Math.min(end,at + PREVIEW_CHARS);
    const left = Math.max(0,at - 24);
    const right = Math.min(chars.length,stop + 24);
    return {char_start:left,char_end:right,segments:[
      {text:chars.slice(left,at).join(''),matched:false},
      {text:chars.slice(at,stop).join(''),matched:true},
      {text:chars.slice(stop,Math.min(end,right)).join(''),matched:stop < end},
      {text:chars.slice(Math.max(stop,end),right).join(''),matched:false},
    ],omitted_before:left > 0,omitted_after:right < chars.length};
  });
}
function safeNumber(value) {
  return Number.isFinite(Number(value)) && value !== null && value !== undefined && Number(value) >= 0 ? Number(value) : undefined;
}
function compact(value) { return Object.fromEntries(Object.entries(value).filter(([,v])=>v!==undefined && v!==null)); }

function evidenceDocument(decision, documents, id) {
  const ref=decision.document_ref;
  if (!ref) return documents.find(d=>d.doc_id===id&&d.evidence_source!=='EVENT_DOCUMENT_VERSION');
  if (ref.basis!=='STABLE_INDEX_VERSION'||ref.doc_id!==id) return undefined;
  return documents.find(d=>d.doc_id===id&&d.evidence_source==='EVENT_DOCUMENT_VERSION'
    && Number(d.version)===ref.version&&d.normalized_sha256===ref.normalized_sha256
    && (typeof d.normalized_text!=='string'||createHash('sha256').update(d.normalized_text).digest('hex')===ref.normalized_sha256));
}

// Read-only, present-day text comparison. These are not historical hash-window coordinates.
export function findMatchingPassages(input, document, inputLocation, documentLocation) {
  const left=Array.from(input),right=Array.from(document);
  const safeInput=Array.from(shown(input)),safeDocument=Array.from(shown(document));
  if (!span(inputLocation,left.length)||!span(documentLocation,right.length)) return [];
  const docEnd=Math.min(documentLocation.char_end,documentLocation.char_start+120000);
  const compactChars=[],coordinateMap=[];
  for(let i=documentLocation.char_start;i<docEnd;i++) {
    if (/\s/u.test(right[i])) continue;
    compactChars.push(right[i]);
    for(let unit=0;unit<right[i].length;unit++) coordinateMap.push(i);
  }
  const compactDocument=compactChars.join('');
  const candidates=[];
  const end=Math.min(inputLocation.char_end,inputLocation.char_start+120000);
  let start=inputLocation.char_start;
  function candidate(stop) {
    while(start<stop&&/\s/u.test(left[start]))start++;
    while(stop>start&&/\s/u.test(left[stop-1]))stop--;
    if(stop-start>=32&&stop-start<=360)candidates.push({start,end:stop,text:left.slice(start,stop).join('')});
  }
  for(let at=start;at<end;at++) {
    const length=at-start;
    if(left[at]==='\n'||(/[.!?。]/u.test(left[at])&&/\s/u.test(left[at+1]??' '))||(length>=220&&/\s/u.test(left[at]))) {
      candidate(at+1);start=at+1;
    }
  }
  candidate(end);
  const passages=[];
  const stride=Math.max(1,Math.floor(candidates.length/30));
  for(let index=0;index<candidates.length&&passages.length<8;index+=stride) {
    const item=candidates[index];
    const needle=item.text.replace(/\s/gu,'');
    if(needle.length<24)continue;
    const found=compactDocument.indexOf(needle);
    if(found<0||compactDocument.indexOf(needle,found+1)>=0)continue;
    const docStart=coordinateMap[found],docStop=coordinateMap[found+needle.length-1]+1;
    const leftText=safeInput.slice(item.start,item.end).join(''),rightText=safeDocument.slice(docStart,docStop).join('');
    // Match before redaction so repeated privacy placeholders cannot create false evidence.
    if(leftText.replace(/[█\s]/gu,'').length<24)continue;
    passages.push({id:`passage-${passages.length+1}`,match_basis:'SAME_TEXT_IGNORING_WHITESPACE',
      input_location:{char_start:item.start,char_end:item.end},document_location:{char_start:docStart,char_end:docStop},
      input_text:leftText,document_text:rightText,nonspace_chars:Array.from(needle).length});
  }
  return passages;
}

// A present-day explanation only: pair different text between two unique, ordered
// identical paragraph anchors. Never guess a replacement from just one anchor.
// Bound work and output; compare before redaction, redact before slicing.
export function findChangedPassages(input, document) {
  const left=Array.from(input),right=Array.from(document);
  if(left.length>40000||right.length>40000)return [];
  const paragraphs=chars=>{
    const result=[];let start=0;
    for(let at=0;at<=chars.length;at++)if(at===chars.length||chars[at]==='\n'){
      let lo=start,hi=at;while(lo<hi&&/\s/u.test(chars[lo]))lo++;while(hi>lo&&/\s/u.test(chars[hi-1]))hi--;
      if(hi>lo)result.push({start:lo,end:hi,key:chars.slice(lo,hi).join('').replace(/\s/gu,'')});
      start=at+1;
    }
    return result;
  };
  const a=paragraphs(left),b=paragraphs(right);
  if(a.length>200||b.length>200)return [];
  const index=new Map(),counts=new Map();
  for(const p of b)index.set(p.key,index.has(p.key)?null:p);
  for(const p of a)counts.set(p.key,(counts.get(p.key)??0)+1);
  const anchors=[];
  for(const p of a){const q=index.get(p.key);if(p.key.length<24||counts.get(p.key)!==1||!q)continue;
    if(anchors.length&&q.start<anchors.at(-1).right.end)return [];
    anchors.push({left:p,right:q});
  }
  const safeLeft=Array.from(shown(input)),safeRight=Array.from(shown(document));
  const gap=(chars,start,end)=>{while(start<end&&/\s/u.test(chars[start]))start++;while(end>start&&/\s/u.test(chars[end-1]))end--;return {start,end,text:chars.slice(start,end).join('')};};
  const result=[];
  for(let at=1;at<anchors.length&&result.length<3;at++){
    const previous=anchors[at-1],next=anchors[at];
    const x=gap(left,previous.left.end,next.left.start),y=gap(right,previous.right.end,next.right.start);
    if(x.text.replace(/\s/gu,'')===y.text.replace(/\s/gu,''))continue;
    if(x.end-x.start>1200||y.end-y.start>1200)continue;
    result.push({id:`change-${result.length+1}`,comparison_basis:'BETWEEN_UNIQUE_IDENTICAL_PARAGRAPHS',
      input_location:{char_start:x.start,char_end:x.end},document_location:{char_start:y.start,char_end:y.end},
      input_text:safeLeft.slice(x.start,Math.min(x.end,x.start+400)).join(''),
      document_text:safeRight.slice(y.start,Math.min(y.end,y.start+400)).join(''),
      input_omitted:x.end-x.start>400,document_omitted:y.end-y.start>400});
  }
  return result;
}

// ───────────────────────── 파일 칸별 전·후 (2026-10-09)
// Gateway가 파일을 칸 단위로 검사한 판정 기록(요청 번호#f:0:docx:body:t1:r2:c1:p0, #f:0:xlsx:s0:r3:c2)으로
// 문서 구조(머리글·문단·표·시트)와 칸마다 원문·보낸 내용을 돌려준다. 파일 원본은 저장하지 않는다.
// masked_text·findings는 Detection이 2026-10-09부터 남긴다 - 그 전 기록은 원문만 있다(after_recorded=false).
// 2026-10-11 PDF·HWP·HWPX 마스킹(명세 §3.7): 칸 번호는 DOCX 문법 그대로 - PDF는 쪽 = 문단(body:p{쪽 번호}, 0부터,
//   Detection이 남긴 쪽 기록), HWP·HWPX는 문단·표 칸(머리말·꼬리말 header{i}·footer{i}). 부가 글자 칸(side:…)은 검사만 한
//   글자라 그리지 않는다(null). Claude는 파일마다 '{요청 번호}#file:{i}#f:…' - segment.file = i, id = 'file{i}:{칸}'
//   (여러 파일의 같은 칸 번호가 섞이지 않게). 가린 파일 재검사 기록('…#verify', '…#nows#verify')은 같은 파일을 한 번 더
//   검사한 것이라 칸으로 세지 않는다(#fileSegments SQL에서도 뺀다)
export const fileSegmentLimit = 3000;
export const fileSegmentTextLimit = 20_000;
const SEGMENT_ID = /(?:#file:(\d{1,4}))?#f:\d+:(docx|xlsx|hwp|hwpx|pdf):([^#]+)$/;

export function isRecheckRequestId(requestId) {
  return String(requestId ?? '').endsWith('#verify');
}

// 찾은 칸과 그 칸 번호가 요청 번호 어디서 시작하는지(index) - 요청 번호 바로 뒤에서 시작하는 것만 그 요청의 칸이다
function matchFileSegment(requestId) {
  const match = SEGMENT_ID.exec(String(requestId ?? ''));
  if (!match) return null;
  const [, file, format, rest] = match;
  let segment = null;
  if (format === 'xlsx') {
    const cell = /^s(\d+):r(\d+):c(\d+)$/.exec(rest);
    if (cell) segment = { id: rest, format, area: 'sheet', sheet: Number(cell[1]), row: Number(cell[2]), col: Number(cell[3]) };
  } else {
    const docx = /^(body|header\d+|footer\d+)((?::t\d+:r\d+:c\d+)*):p(\d+)$/.exec(rest);
    if (docx) {
      const tables = [...docx[2].matchAll(/:t(\d+):r(\d+):c(\d+)/g)].map((m) => m.slice(1).map(Number));
      segment = { id: rest, format, area: docx[1], para: Number(docx[3]) };
      if (tables.length) Object.assign(segment, { table: tables[0][0], row: tables[0][1], col: tables[0][2], nested: tables.length > 1 });
    }
  }
  if (!segment) return null;
  if (file !== undefined) Object.assign(segment, { id: `file${Number(file)}:${rest}`, file: Number(file) });
  return { segment, index: match.index };
}

export function parseFileSegment(requestId) {
  return matchFileSegment(requestId)?.segment ?? null;
}

// replacement가 없는 적중(정책 allow·allow_notify·block_notify, Detection masker)에만 policy_action을 붙인다 - 화면이
// '실제로 바꾼 값'과 '찾았지만 정책상 그대로 둔 값'을 가른다. 둘 다 없는 옛 기록은 지금처럼 가린 값으로 본다
const POLICY_ACTION = /^[a-z_]{1,32}$/;
function maskedSpans(findings, size) {
  if (!Array.isArray(findings)) return [];
  return findings.filter((f) => Number.isInteger(f?.start) && Number.isInteger(f?.end) && f.start >= 0 && f.end > f.start && f.end <= size)
    .map((f) => compact({ start: f.start, end: f.end, entity_type: typeof f.entity_type === 'string' ? f.entity_type : undefined,
      replacement: typeof f.replacement === 'string' ? f.replacement : undefined,
      policy_action: typeof f.replacement !== 'string' && typeof f.policy_action === 'string' && POLICY_ACTION.test(f.policy_action)
        ? f.policy_action : undefined }));
}

// 칸별 전·후는 원문 그대로 보여 주고 가린 값은 하이라이트로만 표시한다(2026-10-09 사용자 결정).
// EVIDENCE_SHOW_RAW 가림 규칙은 문서 일치 비교·마스킹 미리보기 등 다른 근거에만 적용
const original = (value) => String(value ?? '');

export function buildFileComparison(event, rows) {
  const own = Array.isArray(rows) ? rows.filter((row) => !isRecheckRequestId(row?.request_id)) : [];
  if (!own.length) return { status: 'NOT_RECORDED', segments: [] };
  if (own.length > fileSegmentLimit) return { status: 'TOO_LARGE', segments: [] };
  const segments = [];
  const files = new Map();
  let afterRecorded = false;
  let ordered = false;
  for (const row of own) {
    const found = matchFileSegment(row.request_id);
    if (!found || !row.request_id.startsWith(`${event.request_id}#`) || found.index !== String(event.request_id).length) continue;
    const parsed = found.segment;
    if (typeof row.prompt !== 'string') return { status: 'TOO_LARGE', segments: [] };
    // Claude 여러 파일: 파일 번호마다 형식·이름 하나(첫 칸 기록 기준). 이름은 칸 비교와 같이 원문 그대로
    if (parsed.file !== undefined && !files.has(parsed.file)) files.set(parsed.file, compact({ file: parsed.file, format: parsed.format,
      filename: typeof row.filename === 'string' && row.filename ? original(row.filename).slice(0, 240) : undefined }));
    const before = original(row.prompt);
    const findings = typeof row.findings === 'string' ? JSON.parse(row.findings) : row.findings;
    const masked = typeof row.masked_text === 'string';
    if (masked || Array.isArray(findings)) afterRecorded = true;
    if (Number.isInteger(row.block_order)) ordered = true;
    segments.push(compact({
      ...parsed,
      block_order: Number.isInteger(row.block_order) ? row.block_order : undefined,
      before,
      after: masked ? original(row.masked_text) : undefined,
      spans: maskedSpans(findings, Array.from(before).length),
      decided_by: row.decided_by === 'windowhash' || row.decided_by === 'signature' ? row.decided_by : undefined,
      pii_hits: typeof row.pii_hits === 'string' ? row.pii_hits : undefined,
    }));
  }
  if (!segments.length) return { status: 'NOT_RECORDED', segments: [] };
  const result = { status: 'AVAILABLE', format: segments[0].format, after_recorded: afterRecorded, ordered, segments };
  if (files.size) result.files = [...files.values()].sort((a, b) => a.file - b.file);
  return result;
}

// ───────────────────────── 내 요청 기록 (2026-10-09)
// 본인에게 보여 줄 차단·가림 사유(2026-10-10): 검사하지 못했거나 가릴 수 없어 막은 경우의 정해진 코드만.
// 개인정보·보호 문서(pii·doc_excerpt)는 칩으로 이미 보이고, 검사 없이 전송된 허용 건의 사유는 본인 화면에 싣지 않는다
export const OWN_REASON_CODES = new Set([
  'file_uninspectable_image', 'file_uninspectable_scanned_pdf', 'file_uninspectable_other', 'file_too_large',
  'detection_timeout', 'detection_unreachable', 'detection_error', 'detection_parse_error',
  'mask_application_failed', 'file_masking_failed',
]);

export function ownReasonCode(event) {
  const action = event.final_action ?? event.action;
  return (action === 'BLOCK' || action === 'MASK') && OWN_REASON_CODES.has(event.reason_code) ? event.reason_code : undefined;
}

// 질문 한 건의 전·후: Detection 판정 기록의 원문(prompt)·대체본(masked_text)·적중 위치(findings)를 칸 하나짜리 파일 비교 모양으로.
// 내 요청 기록(buildOwnEvidence)과 관리자 근거의 'Gateway 마스킹 본문이 없을 때' 대체(buildMatchEvidence)가 같은 함수를 쓴다
function promptComparison(decision) {
  const before = original(decision.prompt);
  const findings = typeof decision.findings === 'string' ? JSON.parse(decision.findings) : decision.findings;
  const masked = typeof decision.masked_text === 'string';
  return { status: 'AVAILABLE', format: 'docx', after_recorded: masked, ordered: true,
    segments: [compact({ id: 'prompt', format: 'docx', area: 'body', para: 0, before, after: masked ? original(decision.masked_text) : undefined,
      spans: maskedSpans(findings, Array.from(before).length),
      decided_by: decision.decided_by === 'signature' ? 'signature' : undefined })] };
}

// 요청을 보낸 본인에게 보여 줄 근거. 보호 문서 일치는 차단 사실만(문서 이름·구간·본문 없음),
// 민감정보는 전·후. 질문도 파일 비교와 같은 모양(칸 하나)으로 돌려줘 화면이 한 가지로 그린다.
export function buildOwnEvidence(event, decision, fileSegments) {
  const reasonCode = ownReasonCode(event);
  const base = { event_id: event.event_id, status: 'NOT_RECORDED', redaction: 'OFF',
    content_type: event.content_type, final_action: event.final_action ?? event.action,
    ...(reasonCode ? { reason_code: reasonCode } : {}) };
  if ((event.detections ?? []).some((d) => d.detector !== 'SIGNATURE')) return { ...base, status: 'AVAILABLE', protected_document: true };
  const own = decision && decision.request_id === event.request_id ? decision : null;
  // 파일은 칸 기록(docx·xlsx)이 있으면 문서 구조로, 없으면(PDF·TXT 등) 전체 글자 한 칸으로
  const files = event.content_type === 'file' ? buildFileComparison(event, fileSegments) : null;
  if (files && files.status !== 'NOT_RECORDED')
    return compact({ ...base, status: files.status === 'AVAILABLE' ? 'AVAILABLE' : files.status,
      filename: typeof own?.filename === 'string' ? original(own.filename).slice(0, 240) : undefined, file_comparison: files });
  if (!own) return base;
  if (typeof own.prompt !== 'string') return { ...base, status: 'TOO_LARGE' };
  return { ...base, status: 'AVAILABLE', prompt_comparison: promptComparison(own) };
}

export function buildMatchEvidence(event, decisions, documents = [], pageRequest, gatewayEvidence, fileSegments) {
  const base = {event_id:event.event_id,source:'RDS_DECISION_LOG',coordinate_system:'NORMALIZED_UNICODE_CODE_POINTS',comparisons:[],
    redaction:evidenceShowsRaw()?'OFF':'APPLIED'};
  if (!event.request_id || !decisions.length) {
    const age=Date.now()-Date.parse(event.occurred_at);
    return {...base,status:!decisions.length&&event.request_id&&event.detection_outcome!=='UNAVAILABLE'&&age>=-5000&&age<120000?'PENDING':'NOT_RECORDED'};
  }
  if (decisions.length !== 1 || decisions[0].request_id !== event.request_id) return {...base,status:'AMBIGUOUS'};
  const decision = decisions[0];
  const detector = decision.decided_by === 'windowhash' ? 'WINDOW_HASH' : decision.decided_by === 'signature' ? 'SIGNATURE' : null;
  if (event.detection_outcome === 'UNAVAILABLE'
    || (event.detection_outcome === 'MATCH' && !event.detections?.some(d=>d.detector===detector))
    || (event.detection_outcome === 'NO_MATCH' && detector)) return {...base,status:'MISMATCH'};
  const metadata = compact({
    detection_reason:typeof decision.reason==='string'?shown(decision.reason).slice(0,500):undefined,
    detection_ms:safeNumber(decision.total_ms),input_chars:safeNumber(decision.text_chars),
    hash_status:decision.hash_status,signature_status:decision.signature_status,
    input_filename:decision.filename?shown(decision.filename).slice(0,240):undefined,
    input_format:decision.format,input_content_type:decision.content_type,
    decision_at:decision.ts?new Date(decision.ts).toISOString():undefined,
    gateway_final:event.final_action??event.action,
  });
  const result = {...base,status:'AVAILABLE',metadata};
  if (event.content_type === 'file' && Array.isArray(fileSegments)) result.file_comparison = buildFileComparison(event, fileSegments);
  if (detector === 'SIGNATURE') result.mask_comparison = {status:'NOT_RECORDED',
    entity_counts:event.detections?.find(d=>d.detector==='SIGNATURE')?.entity_counts ?? []};
  if (result.mask_comparison && gatewayEvidence?.status==='REQUEST_REWRITTEN'
    && event.final_action==='MASK' && event.enforcement?.applied) {
    const rawBefore=rawBeforePreview(gatewayEvidence.beforePreview,decision.prompt);
    Object.assign(result.mask_comparison,{
      status:'REQUEST_REWRITTEN',before_preview:rawBefore??shown(gatewayEvidence.beforePreview),before_raw:rawBefore!==undefined,
      after_preview:shown(gatewayEvidence.afterPreview),before_chars:gatewayEvidence.beforeChars,
      after_chars:gatewayEvidence.afterChars,preview_truncated:gatewayEvidence.previewTruncated,
      outbound_text_sha256:gatewayEvidence.outboundTextSha256,spans:gatewayEvidence.spans,
    });
  }
  // Gateway가 마스킹 본문을 보내지 않는 질문(Claude 새 화면)은 Detection 판정 기록의 원문·대체본으로 내 요청 기록과 같은 전·후를 붙인다(2026-10-12).
  // Gateway 본문이 있으면(ChatGPT)·파일·문서 일치는 그대로. 원문은 EVIDENCE_SHOW_RAW와 무관하게 하이라이트로 표시(위 original())
  if (result.mask_comparison && result.mask_comparison.status !== 'REQUEST_REWRITTEN' && event.content_type !== 'file'
    && (event.final_action ?? event.action) === 'MASK' && typeof decision.prompt === 'string' && typeof decision.masked_text === 'string') {
    try { result.prompt_comparison = promptComparison(decision); }
    catch { /* 적중 위치 기록이 깨졌으면 전·후를 붙이지 않고 지금처럼 '기록 없음'으로 둔다 */ }
  }
  for (const detection of event.detections ?? []) {
    if (detection.detector !== 'WINDOW_HASH') continue;
    const document = evidenceDocument(decision,documents,detection.matched_document_id);
    const comparison = {document_id:detection.matched_document_id,coverage:detection.score,
      coverage_basis:decision.reason?.includes('확인된 창 구간 덮임 ')?'CONFIRMED_WINDOW_INTERVALS':'LEGACY_BOUNDING_RANGE',
      coverage_sampled:decision.reason?.includes('표본 조회: 실제 일치는 더 넓을 수 있음')??false,
      input_location:detection.input_location,document_location:detection.matched_location,
      input_previews:[],document_previews:[],status:'NOT_RECORDED'};
    comparison.document_source=decision.document_ref?'EVENT_DOCUMENT_VERSION':'CURRENT_PROTECTED_DOCUMENT';
    if (decision.document_ref) Object.assign(comparison,{
      recorded_document_version:String(decision.document_ref.version),
      recorded_document_sha256:decision.document_ref.normalized_sha256,
    });
    if (document) Object.assign(comparison,compact({document_name:document.filename,
      current_document_version:document.version==null?undefined:String(document.version),
      current_classification:document.classification,current_index_status:document.index_status,
      document_chars:safeNumber(document.normalized_chars)}));
    // Reject uncertain joins instead of showing a different prompt or document.
    const expectedInput = detection.input_location;
    const expectedDoc = detection.matched_location;
    if (decision.doc_id!==detection.matched_document_id || !expectedInput || !expectedDoc
      || decision.input_span!==`${expectedInput.char_start}-${expectedInput.char_end}`
      || decision.doc_span!==`${expectedDoc.char_start}-${expectedDoc.char_end}`) comparison.status='MISMATCH';
    else if (safeNumber(decision.prompt_chars)>TEXT_LIMIT || safeNumber(document?.normalized_chars)>TEXT_LIMIT) comparison.status='TOO_LARGE';
    else if (decision.prompt_kept && typeof decision.prompt==='string' && typeof document?.normalized_text==='string') {
      comparison.input_previews=snippets(decision.prompt,expectedInput);
      comparison.document_previews=snippets(document.normalized_text,expectedDoc);
      comparison.status=comparison.input_previews.length && comparison.document_previews.length?'AVAILABLE':'INVALID_RANGE';
      if (comparison.status==='INVALID_RANGE') { comparison.input_previews=[]; comparison.document_previews=[]; }
      else {
        comparison.matching_passages=findMatchingPassages(decision.prompt,document.normalized_text,expectedInput,expectedDoc);
        comparison.current_text_equal_ignoring_whitespace=decision.prompt.replace(/\s/gu,'')===document.normalized_text.replace(/\s/gu,'');
        if(!comparison.current_text_equal_ignoring_whitespace)comparison.changed_passages=findChangedPassages(decision.prompt,document.normalized_text);
      }
    }
    result.comparisons.push(comparison);
  }
  if (pageRequest) {
    result.page = {status:'NOT_RECORDED',side:pageRequest.side,document_id:pageRequest.documentId};
    if (pageRequest.documentId) {
      const comparison = result.comparisons.find(c=>c.document_id===pageRequest.documentId);
      if (comparison?.status==='AVAILABLE') {
        const isInput = pageRequest.side==='input';
        const text = isInput ? decision.prompt : evidenceDocument(decision,documents,pageRequest.documentId)?.normalized_text;
        const location = isInput ? comparison.input_location : comparison.document_location;
        result.page=documentPage(text,location,pageRequest,isInput?'RETAINED_INPUT':comparison.document_source);
      } else if (comparison) result.page.status=comparison.status;
    } else if (pageRequest.side==='input' && detector!=='WINDOW_HASH'
      && decision.prompt_kept && typeof decision.prompt==='string'
      && Array.from(decision.prompt).length<=TEXT_LIMIT) {
      result.page=documentPage(decision.prompt,undefined,pageRequest,'RETAINED_INPUT');
    }
  }
  return result;
}

// ───────────────────────── 같은 글자 비율용 본문(2026-10-16 '일치 비율' 통일)
// 화면 근거 쪽(documentPage)이 주는 것과 같은 본문: 가림(shown) 적용 글 + 가림 구간(원문과 글자가 달라진 곳 = 쪽 조각의 redacted:true).
// 같은 글자 비율은 이 본문으로 화면과 같은 원본(match-ratio.mjs ← 화면 src/utils/matchRatio.ts)이 계산한다
export function maskedBody(text) {
  const original = Array.from(String(text ?? ''));
  const chars = Array.from(shown(text));
  const runs = [];
  for (let at = 0; at < chars.length; at++) {
    if (chars[at] === original[at]) continue;
    const last = runs.at(-1);
    if (last && last.end === at) last.end = at + 1; else runs.push({ start: at, end: at + 1 });
  }
  return { text: chars.join(''), runs };
}

/** 근거 응답의 비교 가운데 본문까지 있는(AVAILABLE) 것마다 입력·문서 본문(화면 쪽 응답과 같은 문서 선택: 사건 당시 보존본 우선) */
export function comparisonBodies(event, decisions, documents = []) {
  const evidence = buildMatchEvidence(event, decisions, documents);
  if (evidence.status !== 'AVAILABLE' || decisions.length !== 1) return [];
  const decision = decisions[0];
  return evidence.comparisons.filter((comparison) => comparison.status === 'AVAILABLE').flatMap((comparison) => {
    const document = evidenceDocument(decision, documents, comparison.document_id);
    if (typeof decision.prompt !== 'string' || typeof document?.normalized_text !== 'string') return [];
    return [{ document_id: comparison.document_id, comparison, input: maskedBody(decision.prompt), document: maskedBody(document.normalized_text) }];
  });
}
