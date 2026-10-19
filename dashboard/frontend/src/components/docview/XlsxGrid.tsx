// XLSX 격자(설계 6.3 XLSX C안): jszip 3.10.2로 압축을 풀고 브라우저 XML 해석으로 시트·공유 문자열·병합·열 너비·굵게·채움을 읽어 표로 그린다.
// 칸 글자는 React 글자 노드로만 넣는다(HTML 해석 없음). 큰 시트는 앞부분만 그리고 안내한다(행·열 제한).
// 시트 탭 · 행/열 머리(첫 행·열 고정) · 표 안 가로 스크롤(4.6 카드 규칙의 예외).
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import JSZip from 'jszip';
import { readSheet, readWorkbook, columnName, type XlsxSheetData, type XlsxWorkbook } from '@/src/utils/docview/xlsx';
import { FIRST_PAINT_TIMEOUT_MS, failureReason, type RendererProps } from './types';

/** 그리는 행·열 상한과 시트 XML 글자 수 상한. 근거: stage3e/README.md 4절(3만 행 시트 실측) */
export const XLSX_LIMITS = { rows: 1000, cols: 100, sheetChars: 60_000_000 } as const;

export default function XlsxGrid({ data, zoom, onInfo, onFailure }: RendererProps) {
  const latest = useRef({ onInfo, onFailure });
  latest.current = { onInfo, onFailure };
  const scrollRef = useRef<HTMLDivElement>(null);
  const tableRef = useRef<HTMLTableElement>(null);
  const [book, setBook] = useState<{ zip: JSZip; workbook: XlsxWorkbook } | null>(null);
  const [sheetIndex, setSheetIndex] = useState(0);
  const [sheet, setSheet] = useState<XlsxSheetData | null>(null);
  const [sheetError, setSheetError] = useState('');
  const painted = useRef(false);
  const started = useRef(performance.now());

  useEffect(() => {
    let cancelled = false;
    painted.current = false;
    started.current = performance.now();
    const timer = window.setTimeout(() => { if (!cancelled && !painted.current) latest.current.onFailure('그리기 제한 시간 초과'); }, FIRST_PAINT_TIMEOUT_MS);
    (async () => {
      const zip = await JSZip.loadAsync(data.slice(0));
      const workbook = await readWorkbook(zip);
      if (cancelled) return;
      const firstVisible = Math.max(0, workbook.sheets.findIndex((item) => !item.hidden));
      setBook({ zip, workbook });
      setSheetIndex(firstVisible);
      latest.current.onInfo({ pages: workbook.sheets.length });
    })().catch((error: unknown) => { if (!cancelled) latest.current.onFailure(failureReason(error)); });
    return () => { cancelled = true; window.clearTimeout(timer); setBook(null); setSheet(null); };
  }, [data]);

  useEffect(() => {
    if (!book) return;
    let cancelled = false;
    setSheet(null);
    setSheetError('');
    readSheet(book.zip, book.workbook, sheetIndex, XLSX_LIMITS).then((next) => {
      if (cancelled) return;
      setSheet(next);
      const cut = next.totalRows > next.rowCount || next.totalCols > next.colCount;
      latest.current.onInfo({ note: cut ? `처음 ${next.rowCount.toLocaleString('ko-KR')}행 · ${columnName(next.colCount - 1)}열까지만 표시(전체 ${next.totalRows.toLocaleString('ko-KR')}행)` : '' });
    }, (error: unknown) => {
      if (cancelled) return;
      // 첫 시트를 못 읽으면 실패(텍스트 보기로), 다른 시트는 그 자리에만 알림
      if (!painted.current) latest.current.onFailure(failureReason(error));
      else setSheetError(failureReason(error));
    });
    return () => { cancelled = true; };
  }, [book, sheetIndex]);

  useLayoutEffect(() => {
    if (!sheet || painted.current) return;
    painted.current = true;
    const ms = Math.round(performance.now() - started.current);
    scrollRef.current?.setAttribute('data-first-paint-ms', String(ms));
    latest.current.onInfo({ firstPaintMs: ms });
  }, [sheet]);

  // 배율: 표에만 CSS zoom(CSSOM). 폭 맞춤은 표 폭이 칸보다 넓을 때만 줄인다
  useLayoutEffect(() => {
    const table = tableRef.current;
    const root = scrollRef.current;
    if (!table || !root) return;
    table.style.zoom = '';
    const natural = table.offsetWidth;
    const value = zoom === 'fit' ? Math.min(1, natural > 0 ? (root.clientWidth - 2) / natural : 1) : zoom;
    table.style.zoom = String(value);
    latest.current.onInfo({ effectiveZoom: value });
  }, [zoom, sheet]);

  if (!book) return <div className="pg-dv-scroll pg-dv-xlsx" ref={scrollRef}><p className="pg-dv-loading" role="status">XLSX를 여는 중…</p></div>;
  return (
    <div className="pg-dv-xlsx-wrap">
      <div className="pg-dv-scroll pg-dv-xlsx" ref={scrollRef} tabIndex={0} aria-label="XLSX 시트">
        {sheetError ? <p className="pg-dv-loading" role="alert">이 시트를 그리지 못함 · {sheetError}</p>
          : !sheet ? <p className="pg-dv-loading" role="status">시트를 읽는 중…</p>
          : <SheetTable sheet={sheet} tableRef={tableRef} name={book.workbook.sheets[sheetIndex]?.name ?? ''} />}
      </div>
      <div className="pg-dv-sheet-tabs" role="tablist" aria-label="시트">
        {book.workbook.sheets.map((item, index) => (
          <button key={`${item.name}-${index}`} type="button" role="tab" aria-selected={index === sheetIndex} className="pg-dv-sheet-tab" onClick={() => setSheetIndex(index)} title={item.hidden ? '원본에서 숨긴 시트' : undefined}>
            {item.name}{item.hidden && <span className="pg-dv-sheet-hidden"> (숨김)</span>}
          </button>
        ))}
      </div>
    </div>
  );
}

function SheetTable({ sheet, name, tableRef }: { sheet: XlsxSheetData; name: string; tableRef: React.RefObject<HTMLTableElement | null> }) {
  if (!sheet.rowCount || !sheet.colCount) return <p className="pg-dv-loading">빈 시트</p>;
  const columns = Array.from({ length: sheet.colCount }, (_, index) => index);
  return (
    // 폭은 열 너비 합(HTML width 속성 — 인라인 style 없이 table-layout: fixed가 열 너비를 지키게)
    <table className="pg-dv-grid" ref={tableRef} aria-label={`${name} 시트`} data-rows={sheet.rowCount} data-cols={sheet.colCount}
      width={44 + sheet.colWidths.reduce((sum, width) => sum + width, 0)}>
      <colgroup>
        <col width={44} />
        {columns.map((col) => <col key={col} width={sheet.colWidths[col]} />)}
      </colgroup>
      <thead>
        <tr>
          <th className="pg-dv-grid-corner" scope="col"><span className="sr-only">행 번호</span></th>
          {columns.map((col) => <th key={col} scope="col" className={sheet.hiddenCols[col] ? 'is-hidden-col' : undefined} title={sheet.hiddenCols[col] ? '원본에서 숨긴 열' : undefined}>{columnName(col)}</th>)}
        </tr>
      </thead>
      <tbody>
        {sheet.cells.map((row, r) => (
          <tr key={r}>
            <th scope="row" className={r < sheet.frozenRows ? 'is-frozen' : undefined}>{r + 1}</th>
            {row.map((cell, c) => {
              if (cell === 'covered') return null;
              if (!cell) return <td key={c} />;
              return (
                <td key={c} rowSpan={cell.rowSpan} colSpan={cell.colSpan} data-kind={cell.kind} data-cell={`${r},${c}`} data-v={cell.value === null ? undefined : String(cell.value)}
                  className={[cell.bold ? 'is-bold' : '', cell.align ? `is-${cell.align}` : '', cell.fill ? 'has-fill' : ''].filter(Boolean).join(' ') || undefined}
                  ref={cell.fill || cell.color ? (element) => { if (!element) return; if (cell.fill) element.style.backgroundColor = cell.fill; if (cell.color) element.style.color = cell.color; } : undefined}>
                  {cell.text}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
