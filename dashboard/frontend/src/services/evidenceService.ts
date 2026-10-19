import { z } from 'zod';
import { httpClient } from '@/src/api/httpClient';
import { parseApiResponse } from '@/src/api/schemas';
import { ApiError } from '@/src/api/errors';

const location = z.object({char_start:z.number().int().nonnegative(),char_end:z.number().int().positive()});
const preview = location.extend({segments:z.array(z.object({text:z.string(),matched:z.boolean()})),omitted_before:z.boolean(),omitted_after:z.boolean()});
const pageStatus=z.enum(['AVAILABLE','NOT_RECORDED','MISMATCH','TOO_LARGE','INVALID_RANGE']);
export const evidencePageSchema=z.object({
  status:pageStatus,side:z.enum(['input','document']),document_id:z.string().optional(),
  char_start:z.number().int().nonnegative().optional(),char_end:z.number().int().nonnegative().optional(),
  total_chars:z.number().int().nonnegative().optional(),page_size:z.literal(1800).optional(),
  segments:z.array(z.object({text:z.string(),matched:z.boolean(),redacted:z.boolean()})).optional(),
  match_location:location.optional(),content_source:z.enum(['RETAINED_INPUT','CURRENT_PROTECTED_DOCUMENT','EVENT_DOCUMENT_VERSION']).optional(),
});
export type EvidencePage=z.infer<typeof evidencePageSchema>;
// 파일 업로드: 칸별 원문·보낸 내용·가린 위치로 문서 구조를 다시 그린다 (2026-10-09). 내 요청 기록의 질문 비교도 같은 모양
// 2026-10-11 PDF(쪽)·HWP·HWPX(문단·표 칸), Claude 여러 파일(file 번호·files 목록), 바꾸지 않은 적중의 policy_action
const fileFormat=z.enum(['docx','xlsx','hwp','hwpx','pdf']);
export const fileComparisonSchema=z.object({
  status:z.enum(['AVAILABLE','NOT_RECORDED','TOO_LARGE']),format:fileFormat.optional(),
  after_recorded:z.boolean().optional(),ordered:z.boolean().optional(),
  files:z.array(z.object({file:z.number().int().nonnegative(),format:fileFormat,filename:z.string().optional()})).optional(),
  segments:z.array(z.object({
    id:z.string(),format:fileFormat,area:z.string(),para:z.number().int().nonnegative().optional(),
    table:z.number().int().nonnegative().optional(),row:z.number().int().nonnegative().optional(),col:z.number().int().nonnegative().optional(),
    nested:z.boolean().optional(),sheet:z.number().int().nonnegative().optional(),block_order:z.number().int().nonnegative().optional(),
    file:z.number().int().nonnegative().optional(),
    before:z.string(),after:z.string().optional(),
    spans:z.array(z.object({start:z.number().int().nonnegative(),end:z.number().int().positive(),entity_type:z.string().optional(),replacement:z.string().optional(),policy_action:z.string().optional()})),
    decided_by:z.enum(['windowhash','signature']).optional(),pii_hits:z.string().optional(),
  })),
});
export const evidenceSchema = z.object({
  event_id:z.string(),source:z.literal('RDS_DECISION_LOG'),
  coordinate_system:z.literal('NORMALIZED_UNICODE_CODE_POINTS'),
  redaction:z.enum(['APPLIED','OFF']).optional(),
  status:z.enum(['AVAILABLE','PENDING','NOT_RECORDED','AMBIGUOUS','MISMATCH']),
  mask_comparison:z.object({status:z.enum(['NOT_RECORDED','REQUEST_REWRITTEN']),entity_counts:z.array(z.object({entity_type:z.string(),count:z.number().int().nonnegative()})),
    before_preview:z.string().optional(),after_preview:z.string().optional(),before_chars:z.number().int().nonnegative().optional(),after_chars:z.number().int().nonnegative().optional(),
    preview_truncated:z.boolean().optional(),before_raw:z.boolean().optional(),outbound_text_sha256:z.string().optional(),
    spans:z.array(z.object({start:z.number().int().nonnegative(),end:z.number().int().positive(),entityType:z.string()})).optional(),
  }).optional(),
  page:evidencePageSchema.optional(),
  file_comparison:fileComparisonSchema.optional(),
  // Gateway 마스킹 본문이 없는 질문 마스킹(Claude 새 화면)의 전·후: Detection 판정 기록(원문·대체본·적중 위치). 내 요청 기록의 질문 비교와 같은 모양 (2026-10-12)
  prompt_comparison:fileComparisonSchema.optional(),
  metadata:z.object({
    detection_reason:z.string().optional(),detection_ms:z.number().nonnegative().optional(),gateway_final:z.enum(['ALLOW','BLOCK','MASK']).optional(),
    input_chars:z.number().nonnegative().optional(),hash_status:z.string().optional(),signature_status:z.string().optional(),
    input_filename:z.string().optional(),input_format:z.string().optional(),input_content_type:z.string().optional(),decision_at:z.string().optional(),
  }).optional(),
  comparisons:z.array(z.object({
    document_id:z.string(),document_name:z.string().optional(),coverage:z.number().min(0).max(1),
    coverage_basis:z.enum(['CONFIRMED_WINDOW_INTERVALS','LEGACY_BOUNDING_RANGE']).optional(),coverage_sampled:z.boolean().optional(),
    input_location:location.optional(),document_location:location,
    input_previews:z.array(preview),document_previews:z.array(preview),
    matching_passages:z.array(z.object({id:z.string(),match_basis:z.literal('SAME_TEXT_IGNORING_WHITESPACE'),input_location:location,document_location:location,input_text:z.string(),document_text:z.string(),nonspace_chars:z.number().int().nonnegative()})).optional(),
    current_document_version:z.string().optional(),current_classification:z.string().optional(),current_index_status:z.string().optional(),document_chars:z.number().optional(),
    document_source:z.enum(['CURRENT_PROTECTED_DOCUMENT','EVENT_DOCUMENT_VERSION']).optional(),recorded_document_version:z.string().optional(),recorded_document_sha256:z.string().optional(),
    current_text_equal_ignoring_whitespace:z.boolean().optional(),
    changed_passages:z.array(z.object({id:z.string(),comparison_basis:z.literal('BETWEEN_UNIQUE_IDENTICAL_PARAGRAPHS'),
      input_location:location.extend({char_end:z.number().int().nonnegative()}),document_location:location.extend({char_end:z.number().int().nonnegative()}),
      input_text:z.string(),document_text:z.string(),input_omitted:z.boolean(),document_omitted:z.boolean()})).optional(),
    status:z.enum(['AVAILABLE','NOT_RECORDED','MISMATCH','TOO_LARGE','INVALID_RANGE']),
  })),
});
export type EventEvidence = z.infer<typeof evidenceSchema>;
function assertEventIdentity(evidence:EventEvidence,eventId:string) {
  if(evidence.event_id!==eventId)throw new ApiError('요청한 사건과 탐지 근거가 일치하지 않습니다.','INVALID_RESPONSE');
}
export const evidenceService = {
  async getPage(eventId:string,side:'input'|'document',offset:number,documentId?:string,signal?:AbortSignal):Promise<EvidencePage> {
    const query=new URLSearchParams({view:side,offset:String(offset)});
    if(documentId)query.set('document_id',documentId);
    const evidence=parseApiResponse(evidenceSchema,await httpClient.get<unknown>(`/api/events/${encodeURIComponent(eventId)}/evidence?${query}`,signal));
    assertEventIdentity(evidence,eventId);
    if(evidence.status!=='AVAILABLE')return {status:evidence.status==='MISMATCH'?'MISMATCH':'NOT_RECORDED',side};
    const page=evidence.page;
    if(!page)return {status:'NOT_RECORDED',side};
    if(page.side!==side || page.document_id!==documentId
      || (page.status==='AVAILABLE' && (page.char_start===undefined || page.char_end===undefined || page.total_chars===undefined
        || page.page_size!==1800 || !page.segments || page.char_end<page.char_start || page.char_end>page.total_chars
        || page.char_start!==Math.min(offset,Math.max(0,Math.floor((page.total_chars-1)/1800)*1800))
        || page.char_end!==Math.min(page.total_chars,page.char_start+1800)
        || Array.from(page.segments.map(segment=>segment.text).join('')).length!==page.char_end-page.char_start
        || (side==='input'?page.content_source!=='RETAINED_INPUT':!['CURRENT_PROTECTED_DOCUMENT','EVENT_DOCUMENT_VERSION'].includes(page.content_source??''))))) {
      throw new ApiError('요청한 본문과 비교 응답이 일치하지 않습니다.','INVALID_RESPONSE');
    }
    return page;
  },
  async getEventEvidence(eventId:string,signal?:AbortSignal):Promise<EventEvidence> {
    const evidence=parseApiResponse(evidenceSchema,await httpClient.get<unknown>(`/api/events/${encodeURIComponent(eventId)}/evidence`,signal));
    assertEventIdentity(evidence,eventId);
    return evidence;
  },
};
