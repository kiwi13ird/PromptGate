// 본문 보기 형식별 그리기 부품(PdfPages·DocxFrame·XlsxGrid·HwpPreview)이 뷰어(DocumentViewer)와 주고받는 약속.
// 각 부품은 자기 스크롤 영역을 가지고, 쪽 수·현재 쪽·실패를 알린다. 실패하면 뷰어가 텍스트 보기로 바꾸고 이유 한 줄을 띄운다.
export type ZoomSetting = number | 'fit';

export interface RenderInfo {
  /** PDF·DOCX 쪽 수(DOCX는 근삿값), XLSX는 시트 수 */
  pages?: number;
  /** 도구 줄에 덧붙일 짧은 안내(예: "처음 1,000행만 표시") */
  note?: string;
  /** 첫 쪽(또는 첫 시트)을 그리는 데 걸린 시간(ms) — 성능 기록용 */
  firstPaintMs?: number;
  /** 폭 맞춤일 때 실제 배율 */
  effectiveZoom?: number;
}

export interface RendererProps {
  data: ArrayBuffer;
  zoom: ZoomSetting;
  /** 도구 줄에서 고른 쪽(1부터). 바뀔 때마다 그 쪽으로 이동 */
  page: number;
  /** 같은 쪽을 다시 골라도 이동하도록 함께 바꾸는 번호 */
  pageJump: number;
  onInfo: (info: RenderInfo) => void;
  onPageChange: (page: number) => void;
  onFailure: (reason: string) => void;
}

/** 그리기 제한 시간: 첫 쪽(첫 시트)이 이 안에 그려지지 않으면 실패로 보고 텍스트 보기로 바꾼다.
 *  값의 근거는 stage3e/README.md 4절(형식별 실측 최댓값의 약 10배). */
export const FIRST_PAINT_TIMEOUT_MS = 30_000;

export function failureReason(error: unknown): string {
  const name = (error as { name?: unknown })?.name;
  if (name === 'PasswordException') return '암호가 걸린 파일';
  if (name === 'InvalidPDFException') return '깨진 PDF 파일';
  if (name === 'XlsxError' || name === 'CfbError') return (error as Error).message || '파일 구조를 읽지 못함';
  const message = String((error as { message?: unknown })?.message ?? '');
  if (/zip|central directory|end of data|corrupted|Can't find end/i.test(message)) return '압축 구조가 깨진 파일';
  return '파일을 해석하지 못함';
}
