// 워터마크(설계 6.6 '권고: 켬'): 관리자 ID · 열람 시각 · 열람 번호(view_ref)를 비스듬히 반복해 본문 위에 겹친다.
// 화면 캡처·사진이 새면 열람 번호로 감사 기록 1건을 찾는 용도(막는 장치는 아님). 누름·선택을 가로막지 않는다(pointer-events: none).
// 스타일은 CSS 클래스로만(인라인 style 없음). 뷰어 스크롤 영역 위에 고정으로 겹친다.
const STAMPS = 40;
const timeFormat = new Intl.DateTimeFormat('ko-KR', { timeZone: 'Asia/Seoul', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });

/** "10.13 09:31" (서울 시각) */
export function watermarkTime(iso: string) {
  const parts = Object.fromEntries(timeFormat.formatToParts(new Date(iso)).map((part) => [part.type, part.value]));
  return `${parts.month}.${parts.day} ${parts.hour}:${parts.minute}`;
}

export function watermarkText({ adminId, issuedAt, viewRef }: { adminId: string; issuedAt: string; viewRef: string }) {
  return `${adminId} · ${watermarkTime(issuedAt)} · 열람 ${viewRef}`;
}

export function Watermark({ text }: { text: string }) {
  return (
    <div className="pg-dv-wm" aria-hidden="true" data-watermark={text}>
      {Array.from({ length: STAMPS }, (_, index) => <span key={index}>{text}</span>)}
    </div>
  );
}
