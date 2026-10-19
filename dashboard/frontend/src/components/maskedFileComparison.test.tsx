import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { evidenceService, fileComparisonSchema, type EventEvidence } from '@/src/services/evidenceService';
import { ownEvidenceSchema } from '@/src/services/myRequestsService';
import { FileComparisonView, type FileComparison } from './FileComparisonView';

// PDF·HWP·HWPX 마스킹 전·후(2026-10-11, PDF·HWP 마스킹 명세 §3.7·§4.6). 값은 모두 가짜
vi.mock('@runtime/ui-mode', async () => import('@/src/config/uiMode.real'));
beforeEach(() => vi.restoreAllMocks());

const RRN = '900101-1234567';
const MAIL = 'fake.person@example.test';
type Seg = FileComparison['segments'][number];
const seg = (over: Partial<Seg>): Seg => ({ id: 'body:p0', format: 'docx', area: 'body', para: 0, before: '', spans: [], ...over });
const at = (text: string, value: string) => {
  const start = Array.from(text.slice(0, text.indexOf(value))).length;
  return { start, end: start + Array.from(value).length };
};

const PHONE = '010-1234-5678';
const pageText = `신청인 주민등록번호 ${RRN}\n연락 메일 ${MAIL}\n전화 ${PHONE}\n`;
const pdf: FileComparison = { status: 'AVAILABLE', format: 'pdf', after_recorded: true, ordered: true, segments: [
  seg({ id: 'body:p2', format: 'pdf', para: 2, block_order: 2, before: pageText, after: pageText.replace(RRN, '[KR_RRN]').replace(PHONE, '[KR_PHONE_NUMBER]'), decided_by: 'signature',
    spans: [{ ...at(pageText, RRN), entity_type: 'KR_RRN', replacement: '[KR_RRN]' }, { ...at(pageText, MAIL), entity_type: 'EMAIL_ADDRESS', policy_action: 'allow' },
      { ...at(pageText, PHONE), entity_type: 'KR_PHONE_NUMBER', replacement: '010-****-5678' }] }),   // 부분 가림 정책도 PDF는 값 전체를 표시로
  seg({ id: 'body:p0', format: 'pdf', para: 0, block_order: 0, before: '가짜 신청서 표지' }),
] };

describe('masked PDF comparison', () => {
  it('draws pages in order and shows the [type] mark written on the erased value', () => {
    render(<FileComparisonView comparison={pdf} />);
    const [before, after] = screen.getAllByRole('article');
    const text = before.textContent ?? '';
    expect(text.indexOf('1쪽')).toBeLessThan(text.indexOf('3쪽'));          // 0부터 센 쪽 번호 → 1쪽·3쪽(글자 없는 쪽은 기록 없음)
    expect(within(before).getByText(RRN).tagName).toBe('MARK');
    expect(within(before).getByText(RRN)).toHaveAttribute('title', '주민등록번호 · 마스킹');
    const box = within(after).getByRole('img', { name: '주민등록번호 · 표시로 바꿈' });
    expect(box).toHaveClass('dops-file-rep', 'box');
    expect(box.textContent).toBe('[KR_RRN]');                                  // 프롬프트·DOCX·HWPX와 같은 표시
    expect(within(after).getByRole('img', { name: '전화번호 · 표시로 바꿈' }).textContent).toBe('[KR_PHONE_NUMBER]');
    expect(within(after).queryByText(RRN)).not.toBeInTheDocument();
    expect(after.textContent).not.toContain('█');
    expect(after.textContent).not.toContain('010-****-5678');
    // 정책상 그대로 보낸 값: 전·후 모두 원문, 하이라이트 대신 점선
    for (const side of [before, after]) {
      const kept = within(side).getByText(MAIL);
      expect(kept.tagName).not.toBe('MARK');
      expect(kept).toHaveClass('dops-file-flagged');
    }
    expect(screen.getByText('대체 표시(PDF)')).toBeInTheDocument();
    expect(screen.queryByText('대체 표시')).not.toBeInTheDocument();
    expect(screen.getByText('PDF는 값을 지우고 같은 자리에 [유형] 표시를 넣어 보냈습니다(부분 마스킹 정책도 값 전체). 쪽 단위로 재구성한 화면입니다.')).toBeInTheDocument();
    expect(screen.queryByText(/검은 상자/)).not.toBeInTheDocument();
  });

  it('does not claim a blocked PDF was sent', () => {
    render(<FileComparisonView comparison={pdf} blocked />);
    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(screen.getByText('차단되어 전송되지 않은 요청입니다.')).toBeInTheDocument();
    expect(screen.getByText('PDF는 쪽 단위로 재구성한 화면입니다.')).toBeInTheDocument();
    expect(screen.queryByText(/표시를 넣어 보냈습니다/)).not.toBeInTheDocument();
    expect(screen.queryByText('대체 표시(PDF)')).not.toBeInTheDocument();
    expect(screen.queryByRole('img', { name: /표시로 바꿈/ })).not.toBeInTheDocument();
    expect(screen.getByText(RRN)).toHaveAttribute('title', '주민등록번호 · 탐지');
  });
});

describe('masked HWP and HWPX comparison', () => {
  const cell = `주민등록번호 ${RRN}`;
  const phone = '연락처 010-1234-5678';
  const mail = `메일 ${MAIL}`;
  const wide = '이름 𠀀가';   // 4바이트 글자(서로게이트 쌍)가 낀 값: 2글자지만 UTF-16 3단위
  const wideLong = '대표 𠀀나';
  const hwp: FileComparison = { status: 'AVAILABLE', format: 'hwp', after_recorded: true, ordered: true, segments: [
    seg({ id: 'body:t0:r0:c1:p0', format: 'hwp', table: 0, row: 0, col: 1, block_order: 0, before: cell, decided_by: 'signature',
      spans: [{ ...at(cell, RRN), entity_type: 'KR_RRN', replacement: '900101-*******' }] }),   // 부분 가림: 길이가 같으면 그 글자
    seg({ id: 'body:p1', format: 'hwp', para: 1, block_order: 1, before: phone, decided_by: 'signature',
      spans: [{ ...at(phone, '010-1234-5678'), entity_type: 'KR_PHONE_NUMBER', replacement: '[KR_PHONE_NUMBER]' }] }),   // 표시(17)가 값(13)보다 김: 같은 길이 '*'
    seg({ id: 'body:p2', format: 'hwp', para: 2, block_order: 2, before: wide, decided_by: 'signature',
      spans: [{ ...at(wide, '𠀀가'), entity_type: 'PERSON', replacement: '[X]' }] }),   // 표시 3 ≤ 3단위: 딱 맞음
    seg({ id: 'body:p3', format: 'hwp', para: 3, block_order: 3, before: mail, decided_by: 'signature',
      spans: [{ ...at(mail, MAIL), entity_type: 'EMAIL_ADDRESS', replacement: '[EMAIL_ADDRESS]' }] }),   // 표시(15) + 빈칸 9 = 값(24)
    seg({ id: 'body:p4', format: 'hwp', para: 4, block_order: 4, before: wideLong, decided_by: 'signature',
      spans: [{ ...at(wideLong, '𠀀나'), entity_type: 'PERSON', replacement: '[PERSON]' }] }),   // 표시 8 > 3단위: 단위마다 '*'
  ] };

  it('shows what HWP actually carries: the [type] mark padded to the same length, else *', () => {
    render(<FileComparisonView comparison={hwp} />);
    const [, after] = screen.getAllByRole('article');
    expect(within(after).getByText('900101-*******')).toHaveAttribute('title', '주민등록번호 · 같은 길이로 덮어씀');
    expect(within(after).getByText('*'.repeat('010-1234-5678'.length))).toBeInTheDocument();
    expect(within(after).queryByText('[KR_PHONE_NUMBER]')).not.toBeInTheDocument();
    const padded = within(after).getByText('[EMAIL_ADDRESS]');
    expect(padded.textContent).toBe('[EMAIL_ADDRESS]' + ' '.repeat(MAIL.length - '[EMAIL_ADDRESS]'.length));
    expect(padded).toHaveClass('dops-file-rep', 'pad');
    expect(getComputedStyle(padded).whiteSpace).toBe('pre');                   // 채운 빈칸이 화면에서 줄지 않게
    expect(within(after).getByText('[X]').textContent).toBe('[X]');            // 서로게이트 쌍 2단위 + 1글자 = 3단위
    expect(within(after).getByText('***')).toBeInTheDocument();               // [PERSON]은 3단위에 안 들어감
    expect(within(after).queryByText('[PERSON]')).not.toBeInTheDocument();
    expect(after.querySelector('table')).not.toBeNull();                       // 표 칸은 표로
    expect(screen.getByText('HWP는 값을 같은 길이로 덮어 보냈습니다([유형] 표시 뒤는 빈칸, 표시가 값보다 길면 *, 부분 마스킹은 그 글자).')).toBeInTheDocument();
    expect(screen.queryByText(/PDF는/)).not.toBeInTheDocument();
  });

  it('shows the replacement mark for HWPX', () => {
    const hwpx: FileComparison = { ...hwp, format: 'hwpx', segments: hwp.segments.map(segment => ({ ...segment, format: 'hwpx' as const })) };
    render(<FileComparisonView comparison={hwpx} />);
    const [, after] = screen.getAllByRole('article');
    expect(within(after).getByText('[KR_PHONE_NUMBER]')).toHaveClass('dops-file-rep');
    expect(within(after).getByText('[EMAIL_ADDRESS]').textContent).toBe('[EMAIL_ADDRESS]');   // HWPX는 빈칸 채움 없음
    expect(screen.getByText('대체 표시')).toBeInTheDocument();
    expect(screen.queryByText(/HWP는 가린 값을/)).not.toBeInTheDocument();
  });
});

describe('several Claude files in one request', () => {
  const claude: FileComparison = { status: 'AVAILABLE', format: 'docx', after_recorded: true, ordered: true,
    files: [{ file: 0, format: 'docx', filename: '가짜 계약서.docx' }, { file: 1, format: 'pdf', filename: '가짜 명세.pdf' }, { file: 2, format: 'hwp' }],
    segments: [
      seg({ id: 'file0:body:p0', file: 0, block_order: 0, before: '계약서 첫 문단' }),
      seg({ id: 'file1:body:p0', file: 1, format: 'pdf', block_order: 0, before: '명세 첫 쪽' }),
      seg({ id: 'file1:body:p1', file: 1, format: 'pdf', para: 1, block_order: 1, before: '명세 둘째 쪽' }),
      seg({ id: 'file2:body:p0', file: 2, format: 'hwp', block_order: 0, before: '한글 첫 문단' }),
    ] };

  it('draws one paper per file with its own format', () => {
    render(<FileComparisonView comparison={claude} />);
    const contract = screen.getByRole('region', { name: '파일 1 · 가짜 계약서.docx' });
    const spec = screen.getByRole('region', { name: '파일 2 · 가짜 명세.pdf' });
    const hangul = screen.getByRole('region', { name: '파일 3 · HWP' });
    expect(within(contract).getAllByRole('article')).toHaveLength(2);
    expect(within(contract).getAllByText('계약서 첫 문단')).toHaveLength(2);
    expect(within(contract).queryByText('명세 첫 쪽')).not.toBeInTheDocument();   // 같은 칸 번호(body:p0)가 섞이지 않는다
    expect(within(spec).getAllByText('2쪽')).toHaveLength(2);
    expect(within(hangul).queryByText(/쪽$/)).not.toBeInTheDocument();
  });
});

describe('new formats in the evidence contract', () => {
  it('accepts PDF, HWP and HWPX segments, file numbers and kept findings', () => {
    expect(fileComparisonSchema.parse(pdf).segments[0].spans[1].policy_action).toBe('allow');
    for (const format of ['hwp', 'hwpx', 'pdf'] as const)
      expect(fileComparisonSchema.safeParse({ status: 'AVAILABLE', format, segments: [seg({ format, file: 1 })], files: [{ file: 1, format }] }).success).toBe(true);
    expect(fileComparisonSchema.safeParse({ status: 'AVAILABLE', format: 'pptx', segments: [] }).success).toBe(false);
    const own = ownEvidenceSchema.parse({ event_id: 'evt-pdf', status: 'AVAILABLE', redaction: 'OFF', content_type: 'file', final_action: 'MASK', file_comparison: pdf });
    expect(own.file_comparison?.format).toBe('pdf');
  });

  it('labels a masked file as sent after masking in the evidence panel', async () => {
    const { EventEvidencePanel } = await import('./EventEvidencePanel');
    const evidence: EventEvidence = { event_id: 'evt-pdf', source: 'RDS_DECISION_LOG', coordinate_system: 'NORMALIZED_UNICODE_CODE_POINTS', status: 'AVAILABLE',
      redaction: 'APPLIED', comparisons: [], mask_comparison: { status: 'NOT_RECORDED', entity_counts: [{ entity_type: 'KR_RRN', count: 1 }] }, file_comparison: pdf };
    vi.spyOn(evidenceService, 'getEventEvidence').mockResolvedValue(evidence);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter><EventEvidencePanel eventId="evt-pdf" finalAction="MASK" /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText('파일 마스킹 전·후')).toBeInTheDocument();
    expect(screen.getByText('민감정보 탐지 · 마스킹 후 전송')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: '주민등록번호 · 표시로 바꿈' })).toHaveTextContent('[KR_RRN]');
  });
});
