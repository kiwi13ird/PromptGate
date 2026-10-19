import JSZip from 'jszip';
import { describe, expect, it } from 'vitest';
import { cellRef, columnName, formatNumber, readSheet, readWorkbook, serialToDateText, XlsxError } from './xlsx';

// 재설계 3h: XLSX 격자 읽기(설계 6.3 C안). 값은 모두 가짜. 실제 테스트베드 파일 대조는 stage3e/viewer-check.mjs(openpyxl 저장값과 칸마다 비교)
const NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';
async function workbook(sheetXml: string, extra: Record<string, string> = {}) {
  const zip = new JSZip();
  zip.file('xl/workbook.xml', `<workbook ${NS}><workbookPr/><sheets><sheet name="급여" sheetId="1" r:id="rId1"/><sheet name="숨김 시트" sheetId="2" state="hidden" r:id="rId2"/></sheets></workbook>`);
  zip.file('xl/_rels/workbook.xml.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
    + '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="/xl/worksheets/sheet2.xml"/>'
    + '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
    + '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>');
  zip.file('xl/sharedStrings.xml', `<sst ${NS}><si><t>이름</t></si><si><r><t>홍</t></r><r><rPr><b/></rPr><t>길동</t></r><rPh><t>ホン</t></rPh></si><si><t>&lt;script&gt;alert(1)&lt;/script&gt;</t></si></sst>`);
  zip.file('xl/styles.xml', `<styleSheet ${NS}><numFmts count="1"><numFmt numFmtId="164" formatCode="#,##0&quot;원&quot;"/></numFmts>`
    + '<fonts><font/><font><b/><color rgb="FF1F4E79"/></font></fonts><fills><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFFF00"/></patternFill></fill></fills>'
    + '<cellXfs><xf numFmtId="0" fontId="0" fillId="0"/><xf numFmtId="14" fontId="0" fillId="0"/><xf numFmtId="164" fontId="1" fillId="2"/><xf numFmtId="10" fontId="0" fillId="0"><alignment horizontal="center"/></xf></cellXfs></styleSheet>');
  zip.file('xl/worksheets/sheet1.xml', sheetXml);
  zip.file('xl/worksheets/sheet2.xml', `<worksheet ${NS}><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>숨김</t></is></c></row></sheetData></worksheet>`);
  for (const [name, text] of Object.entries(extra)) zip.file(name, text);
  return JSZip.loadAsync(await zip.generateAsync({ type: 'uint8array' }));
}
const SHEET = `<worksheet ${NS}><sheetViews><sheetView><pane ySplit="1" state="frozen"/></sheetView></sheetViews><cols><col min="1" max="1" width="20" customWidth="1"/><col min="3" max="3" width="9" hidden="1"/></cols><sheetData>
  <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c></row>
  <row r="2"><c r="A2" s="1"><v>46308</v></c><c r="B2" s="2"><v>1234567</v></c><c r="C2" s="3"><v>0.125</v></c><c r="D2" t="b"><v>1</v></c><c r="E2" t="e"><v>#DIV/0!</v></c></row>
  <row r="4"><c r="A4" t="str"><f>A1</f><v>이름</v></c><c r="B4"><v>0.1</v></c><c r="C4"><v>123456789012</v></c></row>
</sheetData><mergeCells count="1"><mergeCell ref="A3:B3"/></mergeCells></worksheet>`;
const LIMITS = { rows: 1000, cols: 100, sheetChars: 1_000_000 };

describe('xlsx reader', () => {
  it('reads sheets, shared strings (rich text, phonetic hint skipped), stored values and simple formats', async () => {
    const zip = await workbook(SHEET);
    const book = await readWorkbook(zip);
    expect(book.sheets).toEqual([{ name: '급여', path: 'xl/worksheets/sheet1.xml', hidden: false }, { name: '숨김 시트', path: 'xl/worksheets/sheet2.xml', hidden: true }]);
    expect(book.sharedStrings).toEqual(['이름', '홍길동', '<script>alert(1)</script>']);
    const sheet = await readSheet(zip, book, 0, LIMITS);
    expect(sheet.rowCount).toBe(4);
    expect(sheet.colCount).toBe(5);
    expect(sheet.frozenRows).toBe(1);
    const cell = (r: number, c: number) => sheet.cells[r][c];
    // 칸 글자는 글자 그대로(HTML 해석 없음)
    expect(cell(0, 2)).toMatchObject({ text: '<script>alert(1)</script>', value: '<script>alert(1)</script>', kind: 'string' });
    expect(cell(1, 0)).toMatchObject({ text: '2026-10-13', value: 46308, kind: 'date' });
    expect(cell(1, 1)).toMatchObject({ text: '1,234,567원', value: 1234567, kind: 'number', bold: true, fill: '#ffff00', color: '#1f4e79' });
    expect(cell(1, 2)).toMatchObject({ text: '12.50%', value: 0.125, align: 'center' });
    expect(cell(1, 3)).toMatchObject({ text: 'TRUE', value: true, kind: 'boolean' });
    expect(cell(1, 4)).toMatchObject({ text: '#DIV/0!', kind: 'error' });
    expect(cell(3, 0)).toMatchObject({ text: '이름', value: '이름' });   // 수식은 다시 계산하지 않고 저장된 결과
    expect(cell(3, 1)).toMatchObject({ text: '0.1', value: 0.1 });
    expect(cell(3, 2)).toMatchObject({ text: '1.23457E+11', value: 123456789012 });
    expect(cell(2, 0)).toMatchObject({ rowSpan: 1, colSpan: 2 });
    expect(cell(2, 1)).toBe('covered');
    expect(sheet.colWidths[0]).toBe(145);
    expect(sheet.colWidths[1]).toBe(64);
    expect(sheet.hiddenCols[2]).toBe(true);
  });

  it('keeps only the first rows and columns within the limit and reports the real size', async () => {
    const rows = Array.from({ length: 30 }, (_, r) => `<row r="${r + 1}">${Array.from({ length: 8 }, (_, c) => `<c r="${columnName(c)}${r + 1}"><v>${r * 10 + c}</v></c>`).join('')}</row>`).join('');
    const zip = await workbook(`<worksheet ${NS}><sheetData>${rows}</sheetData></worksheet>`);
    const book = await readWorkbook(zip);
    const sheet = await readSheet(zip, book, 0, { rows: 10, cols: 3, sheetChars: 1_000_000 });
    expect([sheet.rowCount, sheet.colCount, sheet.totalRows, sheet.totalCols]).toEqual([10, 3, 30, 8]);
    expect(sheet.cells).toHaveLength(10);
    expect(sheet.cells[9][2]).toMatchObject({ value: 92 });
  });

  it('refuses broken or oversized parts with a reason instead of hanging', async () => {
    const broken = await workbook(`<worksheet ${NS}><sheetData><row r="1"><c r="A1"><v>1</v>`);
    await expect(readSheet(broken, await readWorkbook(broken), 0, LIMITS)).rejects.toMatchObject({ name: 'XlsxError', reason: 'broken' });
    const big = await workbook(SHEET);
    await expect(readSheet(big, await readWorkbook(big), 0, { ...LIMITS, sheetChars: 100 })).rejects.toBeInstanceOf(XlsxError);
    const notXlsx = await JSZip.loadAsync(await new JSZip().file('word/document.xml', '<w/>').generateAsync({ type: 'uint8array' }));
    await expect(readWorkbook(notXlsx)).rejects.toMatchObject({ reason: 'not-xlsx' });
  });

  it('converts references, column names and serial dates', () => {
    expect(cellRef('AB12')).toEqual({ row: 11, col: 27 });
    expect(cellRef('$C$3')).toEqual({ row: 2, col: 2 });
    expect(cellRef('nope')).toBeNull();
    expect([0, 25, 26, 701, 702].map(columnName)).toEqual(['A', 'Z', 'AA', 'ZZ', 'AAA']);
    expect(serialToDateText(46308.5, false, 'yyyy-mm-dd h:mm')).toBe('2026-10-13 12:00');
    expect(serialToDateText(0.25, false, 'h:mm')).toBe('06:00');
    expect(serialToDateText(44846, true, 'yyyy-mm-dd')).toBe('2026-10-13');
    expect(formatNumber(-1500, 3, undefined, false).text).toBe('-1,500');
    expect(formatNumber(1234.5, 0, 'General', false).text).toBe('1234.5');
  });
});
