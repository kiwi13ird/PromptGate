// XLSX 읽기(설계 6.3 XLSX C안: jszip + 브라우저 XML 해석). 저장된 값(수식은 다시 계산하지 않고 저장된 결과)·공유 문자열·
// 병합·열 너비·굵게·단색 채움·시트 탭만 읽는다. 테두리·조건부 서식·차트·그림은 없다.
// 칸 글자는 글자로만 넘긴다(HTML로 해석하지 않음 — 부르는 쪽이 React 글자 노드로만 그린다).
export interface ZipEntryLike {
  async(type: 'string'): Promise<string>;
}
export interface ZipLike {
  file(path: string): ZipEntryLike | null;
}

export interface XlsxSheetRef {
  name: string;
  path: string;
  hidden: boolean;
}

interface CellFormat {
  numFmt?: string;
  numFmtId: number;
  bold: boolean;
  fill?: string;
  color?: string;
  align?: 'left' | 'center' | 'right';
}

export interface XlsxWorkbook {
  sheets: XlsxSheetRef[];
  date1904: boolean;
  sharedStrings: string[];
  formats: CellFormat[];
}

export type XlsxValue = string | number | boolean | null;

export interface XlsxCell {
  /** 화면에 보일 글자(숫자 서식 적용) */
  text: string;
  /** 저장된 값(정답 대조용): 문자열·숫자·참거짓, 오류는 '#DIV/0!' 같은 글자 */
  value: XlsxValue;
  kind: 'string' | 'number' | 'boolean' | 'error' | 'date';
  bold?: boolean;
  fill?: string;
  /** 글자색(RGB로 적힌 것만 — 테마 색은 읽지 않음) */
  color?: string;
  align?: 'left' | 'center' | 'right';
  rowSpan?: number;
  colSpan?: number;
}

export interface XlsxSheetData {
  /** 표시할 행 수(제한 적용 후) · 원래 마지막 행 */
  rowCount: number;
  totalRows: number;
  colCount: number;
  totalCols: number;
  /** cells[행][열] (0부터). 병합으로 가려진 칸은 'covered' */
  cells: Array<Array<XlsxCell | 'covered' | null>>;
  /** 열 너비(px, 0부터). 지정 없으면 기본 64 */
  colWidths: number[];
  hiddenCols: boolean[];
  frozenRows: number;
  frozenCols: number;
  merges: number;
}

export interface XlsxLimits {
  rows: number;
  cols: number;
  /** 시트 XML 글자 수 상한(이보다 크면 해석하지 않고 오류) */
  sheetChars: number;
}

export class XlsxError extends Error {
  constructor(message: string, readonly reason: 'not-xlsx' | 'broken' | 'too-large') {
    super(message);
    this.name = 'XlsxError';
  }
}

const DEFAULT_COL_PX = 64;

function parseXml(text: string, what: string) {
  const document = new DOMParser().parseFromString(text, 'application/xml');
  if (document.getElementsByTagName('parsererror').length) throw new XlsxError(`${what} XML을 해석하지 못함`, 'broken');
  return document;
}
const all = (node: Document | Element, local: string) => Array.from(node.getElementsByTagNameNS('*', local));
const kids = (node: Element, local: string) => Array.from(node.children).filter((child) => child.localName === local);
const kid = (node: Element, local: string) => Array.from(node.children).find((child) => child.localName === local) ?? null;
const relId = (node: Element) => node.getAttribute('r:id') ?? Array.from(node.attributes).find((attribute) => attribute.localName === 'id' && attribute.namespaceURI?.includes('relationships'))?.value ?? null;

function resolveTarget(base: string, target: string) {
  if (target.startsWith('/')) return target.slice(1);
  const parts = base.split('/').slice(0, -1);
  for (const piece of target.split('/')) {
    if (piece === '..') parts.pop();
    else if (piece !== '.' && piece !== '') parts.push(piece);
  }
  return parts.join('/');
}

async function readText(zip: ZipLike, path: string) {
  const entry = zip.file(path);
  return entry ? entry.async('string') : null;
}

/** 공유 문자열 1개: <t> 또는 서식 조각 <r><t>…</t></r>. 읽는 법 표시(<rPh>)는 뺀다 */
function sharedText(si: Element) {
  const direct = kid(si, 't');
  if (direct) return direct.textContent ?? '';
  return kids(si, 'r').map((run) => kid(run, 't')?.textContent ?? '').join('');
}

export async function readWorkbook(zip: ZipLike): Promise<XlsxWorkbook> {
  const workbookText = await readText(zip, 'xl/workbook.xml');
  if (workbookText === null) throw new XlsxError('xl/workbook.xml이 없음', 'not-xlsx');
  const workbook = parseXml(workbookText, '통합 문서');
  const relsText = await readText(zip, 'xl/_rels/workbook.xml.rels');
  const rels = new Map<string, { target: string; type: string }>();
  if (relsText) for (const rel of all(parseXml(relsText, '관계'), 'Relationship')) rels.set(rel.getAttribute('Id') ?? '', { target: rel.getAttribute('Target') ?? '', type: rel.getAttribute('Type') ?? '' });
  const relOfType = (suffix: string) => [...rels.values()].find((rel) => rel.type.endsWith(suffix));

  const sheets = all(workbook, 'sheet').map((sheet, index): XlsxSheetRef => {
    const rel = rels.get(relId(sheet) ?? '');
    return {
      name: sheet.getAttribute('name') ?? `시트 ${index + 1}`,
      path: rel ? resolveTarget('xl/workbook.xml', rel.target) : `xl/worksheets/sheet${index + 1}.xml`,
      hidden: ['hidden', 'veryHidden'].includes(sheet.getAttribute('state') ?? ''),
    };
  });
  if (!sheets.length) throw new XlsxError('시트가 없음', 'broken');
  const properties = all(workbook, 'workbookPr')[0];
  const date1904 = ['1', 'true'].includes(properties?.getAttribute('date1904') ?? '');

  const sharedRel = relOfType('/sharedStrings');
  const sharedText_ = await readText(zip, sharedRel ? resolveTarget('xl/workbook.xml', sharedRel.target) : 'xl/sharedStrings.xml');
  const sharedStrings = sharedText_ ? all(parseXml(sharedText_, '공유 문자열'), 'si').map(sharedText) : [];

  const stylesRel = relOfType('/styles');
  const stylesText = await readText(zip, stylesRel ? resolveTarget('xl/workbook.xml', stylesRel.target) : 'xl/styles.xml');
  return { sheets, date1904, sharedStrings, formats: stylesText ? readFormats(parseXml(stylesText, '서식')) : [] };
}

/** 'FFRRGGBB'·'RRGGBB' → '#rrggbb'. 그 밖(테마·색인 색)은 읽지 않는다 */
function rgbColor(rgb: string | null | undefined) {
  if (!rgb) return undefined;
  return /^[0-9A-Fa-f]{8}$/.test(rgb) ? `#${rgb.slice(2).toLowerCase()}` : /^[0-9A-Fa-f]{6}$/.test(rgb) ? `#${rgb.toLowerCase()}` : undefined;
}

function readFormats(styles: Document): CellFormat[] {
  const numFmts = new Map<number, string>();
  for (const format of all(styles, 'numFmt')) numFmts.set(Number(format.getAttribute('numFmtId')), format.getAttribute('formatCode') ?? '');
  const fontsNode = all(styles, 'fonts')[0];
  const fonts = fontsNode ? kids(fontsNode, 'font').map((font) => {
    const bold = kid(font, 'b');
    return { bold: Boolean(bold) && !['0', 'false'].includes(bold?.getAttribute('val') ?? ''), color: rgbColor(kid(font, 'color')?.getAttribute('rgb')) };
  }) : [];
  const fillsNode = all(styles, 'fills')[0];
  const fills = fillsNode ? kids(fillsNode, 'fill').map((fill) => {
    const pattern = kid(fill, 'patternFill');
    if (pattern?.getAttribute('patternType') !== 'solid') return undefined;
    return rgbColor(kid(pattern, 'fgColor')?.getAttribute('rgb'));
  }) : [];
  const xfsNode = all(styles, 'cellXfs')[0];
  if (!xfsNode) return [];
  return kids(xfsNode, 'xf').map((xf) => {
    const numFmtId = Number(xf.getAttribute('numFmtId') ?? 0);
    const horizontal = kid(xf, 'alignment')?.getAttribute('horizontal');
    return {
      numFmtId,
      numFmt: numFmts.get(numFmtId),
      bold: fonts[Number(xf.getAttribute('fontId') ?? 0)]?.bold ?? false,
      color: fonts[Number(xf.getAttribute('fontId') ?? 0)]?.color,
      fill: fills[Number(xf.getAttribute('fillId') ?? 0)],
      align: horizontal === 'left' || horizontal === 'center' || horizontal === 'right' ? horizontal : undefined,
    };
  });
}

/** "C12" → { row: 11, col: 2 } (0부터) */
export function cellRef(ref: string) {
  const match = /^\$?([A-Z]{1,3})\$?(\d{1,7})$/i.exec(ref.trim());
  if (!match) return null;
  let col = 0;
  for (const char of match[1].toUpperCase()) col = col * 26 + (char.charCodeAt(0) - 64);
  return { row: Number(match[2]) - 1, col: col - 1 };
}

export function columnName(index: number) {
  let name = '';
  for (let value = index + 1; value > 0; value = Math.floor((value - 1) / 26)) name = String.fromCharCode(65 + ((value - 1) % 26)) + name;
  return name;
}

// ───── 숫자 서식(간단판): 날짜·시각·퍼센트·천 단위·소수 자리. 그 밖은 Excel '일반'처럼 ─────
const BUILTIN_FORMATS: Record<number, string> = {
  1: '0', 2: '0.00', 3: '#,##0', 4: '#,##0.00', 9: '0%', 10: '0.00%', 11: '0.00E+00',
  14: 'yyyy-mm-dd', 15: 'd-mmm-yy', 16: 'd-mmm', 17: 'mmm-yy', 18: 'h:mm AM/PM', 19: 'h:mm:ss AM/PM', 20: 'h:mm', 21: 'h:mm:ss', 22: 'yyyy-mm-dd h:mm',
  37: '#,##0 ;(#,##0)', 38: '#,##0 ;[Red](#,##0)', 39: '#,##0.00;(#,##0.00)', 40: '#,##0.00;[Red](#,##0.00)', 45: 'mm:ss', 46: '[h]:mm:ss', 47: 'mmss.0', 49: '@',
};
// 한국어 환경 날짜 번호(27~36, 50~58)
const LOCALE_DATE_IDS = new Set([27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 50, 51, 52, 53, 54, 55, 56, 57, 58]);

const stripLiterals = (format: string) => format.replace(/"[^"]*"/g, '').replace(/\\./g, '').replace(/\[[^\]]*\]/g, (block) => (/^\[(h+|m+|s+)\]$/i.test(block) ? block : ''));

export function isDateFormat(numFmtId: number, format: string | undefined) {
  if ((numFmtId >= 14 && numFmtId <= 22) || (numFmtId >= 45 && numFmtId <= 47) || LOCALE_DATE_IDS.has(numFmtId)) return true;
  if (!format) return false;
  const section = stripLiterals(format.split(';')[0]);
  return /[ymdhs]/i.test(section) && !/^general$/i.test(section.trim());
}

const pad = (value: number) => String(value).padStart(2, '0');

export function serialToDateText(serial: number, date1904: boolean, format: string | undefined) {
  const section = stripLiterals((format ?? '').split(';')[0]).toLowerCase();
  const hasDate = !format || /[yd]/.test(section) || (/m/.test(section) && !/[hs]/.test(section));
  const hasTime = /[hs]/.test(section) || (!format && !Number.isInteger(serial));
  const epoch = date1904 ? Date.UTC(1904, 0, 1) : Date.UTC(1899, 11, 30);
  const at = new Date(epoch + Math.round(serial * 86_400_000));
  const date = `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}`;
  const time = `${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())}${/s/.test(section) ? `:${pad(at.getUTCSeconds())}` : ''}`;
  if (hasDate && hasTime) return `${date} ${time}`;
  return hasTime ? time : date;
}

function decimalsOf(section: string) {
  const match = /\.([0#]+)/.exec(section);
  return match ? match[1].length : 0;
}

// "1.23e+5" → "1.23E+05"(Excel 표기: 지수 두 자리)
const excelExponent = (text: string) => text.toUpperCase().replace(/E([+-])(\d)$/, 'E$10$2');

export function formatGeneral(value: number) {
  if (!Number.isFinite(value)) return String(value);
  if (Number.isInteger(value) && Math.abs(value) < 1e11) return String(value);
  const rounded = Number(value.toPrecision(11));
  if (Math.abs(rounded) >= 1e11 || (rounded !== 0 && Math.abs(rounded) < 1e-9)) return excelExponent(rounded.toExponential(5).replace(/\.?0+e/, 'e'));
  return String(rounded);
}

export function formatNumber(value: number, numFmtId: number, format: string | undefined, date1904: boolean) {
  const code = format ?? BUILTIN_FORMATS[numFmtId];
  if (isDateFormat(numFmtId, format)) return { text: serialToDateText(value, date1904, code), date: true };
  if (!code || /^general$/i.test(code.trim()) || code === '@') return { text: formatGeneral(value), date: false };
  const sections = code.split(';');
  const section = value < 0 && sections[1] ? sections[1] : sections[0];
  const bare = stripLiterals(section);
  const literals = (where: 'before' | 'after') => {
    const quoted = [...section.matchAll(/"([^"]*)"/g)];
    const firstDigit = section.search(/[0#?]/);
    return quoted.filter((match) => (where === 'before' ? (match.index ?? 0) < firstDigit : (match.index ?? 0) > firstDigit)).map((match) => match[1]).join('');
  };
  const sign = value < 0 && !sections[1] ? '-' : '';
  const magnitude = Math.abs(value);
  let body: string;
  if (/%/.test(bare)) body = `${(magnitude * 100).toFixed(decimalsOf(bare))}%`;
  else if (/E\+/i.test(bare)) body = excelExponent(magnitude.toExponential(decimalsOf(bare)));
  else if (/[0#]/.test(bare)) {
    const decimals = decimalsOf(bare);
    body = /#,##|0,0/.test(bare)
      ? magnitude.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })
      : magnitude.toFixed(decimals);
  } else body = formatGeneral(magnitude);
  return { text: `${literals('before')}${sign}${body}${literals('after')}`, date: false };
}

/** 시트 하나를 읽는다. 행·열 제한을 넘는 부분은 세기만 하고 칸을 만들지 않는다 */
export async function readSheet(zip: ZipLike, workbook: XlsxWorkbook, index: number, limits: XlsxLimits): Promise<XlsxSheetData> {
  const ref = workbook.sheets[index];
  if (!ref) throw new XlsxError('없는 시트', 'broken');
  const text = await readText(zip, ref.path);
  if (text === null) throw new XlsxError(`${ref.path}가 없음`, 'broken');
  if (text.length > limits.sheetChars) throw new XlsxError('시트가 너무 큼', 'too-large');
  const sheet = parseXml(text, '시트');

  const values: Array<Array<XlsxCell | 'covered' | null>> = [];
  let totalRows = 0;
  let totalCols = 0;
  let rowCursor = -1;
  for (const row of all(sheet, 'row')) {
    const rowNumber = Number(row.getAttribute('r'));
    const r = Number.isInteger(rowNumber) && rowNumber > 0 ? rowNumber - 1 : rowCursor + 1;
    rowCursor = r;
    let colCursor = -1;
    for (const cell of kids(row, 'c')) {
      const position = cellRef(cell.getAttribute('r') ?? '');
      const c = position ? position.col : colCursor + 1;
      colCursor = c;
      const read = readCell(cell, workbook);
      if (!read) continue;
      totalRows = Math.max(totalRows, r + 1);
      totalCols = Math.max(totalCols, c + 1);
      if (r >= limits.rows || c >= limits.cols) continue;
      (values[r] ??= [])[c] = read;
    }
  }

  // 병합: 왼쪽 위 칸에 rowSpan·colSpan, 나머지는 covered. 병합 범위도 마지막 행·열에 넣는다(빈 병합 칸)
  let merges = 0;
  for (const merge of all(sheet, 'mergeCell')) {
    const [startRef, endRef] = (merge.getAttribute('ref') ?? '').split(':');
    const start = cellRef(startRef ?? '');
    const end = cellRef(endRef ?? startRef ?? '');
    if (!start || !end || end.row < start.row || end.col < start.col) continue;
    merges += 1;
    totalRows = Math.max(totalRows, end.row + 1);
    totalCols = Math.max(totalCols, end.col + 1);
    if (start.row >= limits.rows || start.col >= limits.cols) continue;
    const lastRow = Math.min(end.row, limits.rows - 1);
    const lastCol = Math.min(end.col, limits.cols - 1);
    const head = values[start.row]?.[start.col];
    const anchor: XlsxCell = head && head !== 'covered' ? head : { text: '', value: null, kind: 'string' };
    anchor.rowSpan = lastRow - start.row + 1;
    anchor.colSpan = lastCol - start.col + 1;
    (values[start.row] ??= [])[start.col] = anchor;
    for (let r = start.row; r <= lastRow; r += 1)
      for (let c = start.col; c <= lastCol; c += 1) if (r !== start.row || c !== start.col) (values[r] ??= [])[c] = 'covered';
  }

  const rowCount = Math.min(totalRows, limits.rows);
  const colCount = Math.min(totalCols, limits.cols);
  const colWidths = Array.from({ length: colCount }, () => DEFAULT_COL_PX);
  const hiddenCols = Array.from({ length: colCount }, () => false);
  for (const col of all(sheet, 'col')) {
    const min = Number(col.getAttribute('min'));
    const max = Number(col.getAttribute('max'));
    const width = Number(col.getAttribute('width'));
    if (!Number.isInteger(min) || !Number.isInteger(max) || min < 1) continue;
    for (let c = min - 1; c <= Math.min(max - 1, colCount - 1); c += 1) {
      // Excel 글자 폭 → 화소(맑은 고딕 11pt 기준 약 7px + 여백 5px)
      if (Number.isFinite(width) && width > 0) colWidths[c] = Math.round(width * 7 + 5);
      if (['1', 'true'].includes(col.getAttribute('hidden') ?? '')) hiddenCols[c] = true;
    }
  }
  const pane = all(sheet, 'pane')[0];
  const frozen = pane && ['frozen', 'frozenSplit'].includes(pane.getAttribute('state') ?? '');
  const cells = Array.from({ length: rowCount }, (_, r) => Array.from({ length: colCount }, (_, c) => values[r]?.[c] ?? null));
  return {
    rowCount, totalRows, colCount, totalCols, cells, colWidths, hiddenCols, merges,
    frozenRows: frozen ? Math.max(0, Math.floor(Number(pane.getAttribute('ySplit') ?? 0))) : 0,
    frozenCols: frozen ? Math.max(0, Math.floor(Number(pane.getAttribute('xSplit') ?? 0))) : 0,
  };
}

function readCell(cell: Element, workbook: XlsxWorkbook): XlsxCell | null {
  const type = cell.getAttribute('t') ?? 'n';
  const format = workbook.formats[Number(cell.getAttribute('s') ?? 0)];
  const style = { ...(format?.bold ? { bold: true } : {}), ...(format?.fill ? { fill: format.fill } : {}), ...(format?.color && format.color !== '#000000' ? { color: format.color } : {}), ...(format?.align ? { align: format.align } : {}) };
  const raw = kid(cell, 'v')?.textContent ?? null;
  if (type === 'inlineStr') {
    const inline = kid(cell, 'is');
    const text = inline ? sharedText(inline) : '';
    return { text, value: text, kind: 'string', ...style };
  }
  if (raw === null) return Object.keys(style).length ? { text: '', value: null, kind: 'string', ...style } : null;
  if (type === 's') {
    const text = workbook.sharedStrings[Number(raw)] ?? '';
    return { text, value: text, kind: 'string', ...style };
  }
  if (type === 'str' || type === 'd') return { text: raw, value: raw, kind: 'string', ...style };
  if (type === 'b') return { text: raw === '1' ? 'TRUE' : 'FALSE', value: raw === '1', kind: 'boolean', align: 'center', ...style };
  if (type === 'e') return { text: raw, value: raw, kind: 'error', align: 'center', ...style };
  const number = Number(raw);
  if (!Number.isFinite(number)) return { text: raw, value: raw, kind: 'string', ...style };
  const formatted = formatNumber(number, format?.numFmtId ?? 0, format?.numFmt, workbook.date1904);
  return { text: formatted.text, value: number, kind: formatted.date ? 'date' : 'number', align: 'right', ...style };
}
