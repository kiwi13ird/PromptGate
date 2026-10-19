// HWP·HWPX 보호 문서 등록 판별(2026-10-11, PDF·HWP 마스킹 명세 1단계 §2.4)
// Detection·Gateway 공통 모듈 hwpdoc.sniff와 같은 규칙. 글자 추출·닫힌 목록 검사는 하지 않음(인덱서가 함).
//   hwp : CFB 머리 + 1536바이트 이상 + 최상위 FileHeader 스트림 첫 32바이트가 'HWP Document File'(뒤 0바이트 무시)
//         → DOC·XLS·암호 걸린 OOXML 같은 다른 CFB는 FileHeader가 없어 거절
//   hwpx: ZIP 머리 + mimetype 항목 내용이 application/hwp+zip (mimetype 항목이 없으면 Contents/content.hpf가 있을 때)
//         → DOCX·XLSX 등 다른 ZIP은 거절
// CFB는 olefile 0.47, ZIP은 Python 3.11.9 zipfile(항목 겹침 검사 포함)이 읽는 방식을 따름. 다른 점(조작된 파일에서만 생김):
//   순환 사슬이 파일 크기보다 길어지면 거절, mimetype이 bzip2·lzma 압축이거나 64KiB 넘게 풀리면 거절,
//   디렉터리 형제 사슬이 약 1000단을 넘으면 olefile은 재귀 한도로 실패하지만 여기서는 읽음(인덱서가 오류로 표시)
import { constants as zlibConstants, crc32, inflateRawSync } from 'node:zlib';

const CFB_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const HWP_SIGNATURE = Buffer.from('HWP Document File', 'ascii');
const HWPX_MIMETYPE = 'application/hwp+zip';

export function sniffHangulDocument(data) {
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
  try {
    if (buffer.length >= 8 && buffer.subarray(0, 8).equals(CFB_MAGIC))
      return cfbHasHwpHeader(buffer) ? 'hwp' : null;
    if (buffer.length >= 4 && buffer.subarray(0, 4).equals(ZIP_MAGIC))
      return zipIsHwpx(buffer) ? 'hwpx' : null;
  } catch {
    // hwpdoc.sniff와 같이 해석 중 오류는 모두 '아님'
  }
  return null;
}

// ---------------------------------------------------------------- CFB (olefile 0.47)

const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const NOSTREAM = 0xffffffff;
const STGTY_STREAM = 2;
const MINI_STREAM_CUTOFF = 4096;
const utf16Name = new TextDecoder('utf-16le', { ignoreBOM: true });

function uint32Array(bytes) {
  if (bytes.length % 4) throw new Error('sector array');
  const values = new Array(bytes.length / 4);
  for (let index = 0; index < values.length; index += 1) values[index] = bytes.readUInt32LE(index * 4);
  return values;
}

function cfbHasHwpHeader(buffer) {
  if (buffer.length < 1536) return false;
  const sectorShift = buffer.readUInt16LE(30);
  const miniShift = buffer.readUInt16LE(32);
  // olefile도 이 범위 밖이면 해석에 실패함(구역 크기 1·2바이트, 파일보다 큰 구역)
  if (sectorShift < 2 || sectorShift > 30) return false;
  const sectorSize = 2 ** sectorShift;
  const miniSectorSize = 2 ** miniShift;
  const numFatSectors = buffer.readUInt32LE(44);
  const firstDirSector = buffer.readUInt32LE(48);
  const firstMiniFatSector = buffer.readUInt32LE(60);
  const numMiniFatSectors = buffer.readUInt32LE(64);
  const firstDifatSector = buffer.readUInt32LE(68);
  const numDifatSectors = buffer.readUInt32LE(72);
  const nbSect = Math.ceil(buffer.length / sectorSize) - 1;

  const sectorStart = (sect) => {
    const start = sectorSize * (sect + 1);
    if (start + sectorSize > buffer.length) throw new Error('incomplete sector');
    return start;
  };
  const fat = [];
  const loadFatSect = (entries) => {
    for (const sect of entries) {
      if (sect === ENDOFCHAIN || sect === FREESECT) break;
      const start = sectorStart(sect);
      // olefile은 FAT을 다 읽은 뒤 nbSect로 자름. 넘치는 구역은 범위 확인만
      if (fat.length < nbSect) for (let at = 0; at < sectorSize; at += 4) fat.push(buffer.readUInt32LE(start + at));
    }
  };
  loadFatSect(uint32Array(buffer.subarray(76, 512)));
  if (numDifatSectors !== 0) {
    if (firstDifatSector >= nbSect) return false;
    const perSector = sectorSize / 4 - 1;
    const nbDifat = Math.floor((numFatSectors - 109 + perSector - 1) / perSector);
    if (numDifatSectors !== nbDifat || nbDifat > nbSect) return false;
    // 같은 DIFAT 구역을 다시 만나면 사슬이 끝나지 않음 → olefile도 'incorrect end of DIFAT'로 실패
    const seen = new Set();
    let sect = firstDifatSector;
    for (let index = 0; index < nbDifat; index += 1) {
      if (seen.has(sect)) return false;
      seen.add(sect);
      const start = sectorStart(sect);
      const difat = uint32Array(buffer.subarray(start, start + sectorSize));
      loadFatSect(difat.slice(0, perSector));
      sect = difat[perSector];
    }
    if (sect !== ENDOFCHAIN && sect !== FREESECT) return false;
  }
  if (fat.length > nbSect) fat.length = nbSect;

  // olefile OleStream: 사슬을 따라 구역을 이어 붙이고 끊기면 거기까지. size가 없으면 FAT 전체 길이까지.
  // 순환 사슬은 olefile처럼 따라가되, 선언 크기가 파일보다 커서 파일보다 많이 읽게 되면 거절
  const readChain = (source, start, size, offset, unit, table) => {
    const unknown = size === undefined;
    const want = unknown ? table.length * unit : size;
    const sectors = Math.ceil(want / unit);
    const chunks = [];
    let total = 0;
    let sect = start;
    for (let index = 0; index < sectors; index += 1) {
      if (sect === ENDOFCHAIN && unknown) break;
      if (sect >= table.length) break;
      const at = offset + unit * sect;
      const chunk = source.subarray(at, at + unit);
      chunks.push(chunk);
      total += chunk.length;
      if (total >= want) break;
      if (total > buffer.length) throw new Error('cyclic chain');
      sect = table[sect];
    }
    const data = Buffer.concat(chunks);
    return data.length >= want ? data.subarray(0, want) : data;
  };

  const directory = readChain(buffer, firstDirSector, undefined, sectorSize, sectorSize, fat);
  const maxEntries = Math.floor(directory.length / 128);
  if (maxEntries === 0) return false;
  const entries = new Array(maxEntries);
  const load = (sid) => {
    if (entries[sid]) return entries[sid];
    const raw = directory.subarray(sid * 128, sid * 128 + 128);
    const nameLength = Math.min(raw.readUInt16LE(64), 64);
    const nameEnd = nameLength - 2 < 0 ? nameLength - 2 + 64 : nameLength - 2;
    const sizeLow = raw.readUInt32LE(120);
    entries[sid] = {
      name: utf16Name.decode(raw.subarray(0, nameEnd)),
      type: raw[66],
      left: raw.readUInt32LE(68),
      right: raw.readUInt32LE(72),
      child: raw.readUInt32LE(76),
      start: raw.readUInt32LE(116),
      size: sectorSize === 512 ? sizeLow : sizeLow + raw.readUInt32LE(124) * 2 ** 32,
      used: false,
      kids: [],
    };
    return entries[sid];
  };
  const appendKids = (parent, sid) => {
    if (sid === NOSTREAM || sid >= maxEntries) return;
    const child = load(sid);
    if (child.used) return;
    child.used = true;
    appendKids(parent, child.left);
    parent.kids.push(child);
    appendKids(parent, child.right);
    buildTree(child);
  };
  const buildTree = (node) => {
    if (node.child === NOSTREAM) return;
    appendKids(node, node.child);
    node.kids.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  };
  const root = load(0);
  buildTree(root);

  const fileHeader = root.kids.find((kid) => kid.name.toLowerCase() === 'fileheader');
  if (!fileHeader || fileHeader.type !== STGTY_STREAM) return false;
  if (fileHeader.size < 32 || fileHeader.size > buffer.length) return false;
  let stream;
  if (fileHeader.size < MINI_STREAM_CUTOFF) {
    if (miniShift > 62) return false; // olefile: 미니 구역 읽기 크기가 Python 정수 범위를 넘어 실패
    const miniFatBytes = readChain(buffer, firstMiniFatSector, numMiniFatSectors * sectorSize, sectorSize, sectorSize, fat);
    const miniSectors = root.size === 0 ? 0 : Math.floor((root.size - 1) / miniSectorSize) + 1;
    const miniFat = uint32Array(miniFatBytes).slice(0, miniSectors);
    const miniStream = readChain(buffer, root.start, root.size, sectorSize, sectorSize, fat);
    stream = readChain(miniStream, fileHeader.start, fileHeader.size, 0, miniSectorSize, miniFat);
  } else {
    stream = readChain(buffer, fileHeader.start, fileHeader.size, sectorSize, sectorSize, fat);
  }
  let end = Math.min(stream.length, 32);
  while (end > 0 && stream[end - 1] === 0) end -= 1;
  return stream.subarray(0, end).equals(HWP_SIGNATURE);
}

// ---------------------------------------------------------------- ZIP (Python 3.11 zipfile)

const EOCD_SIGNATURE = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const MAX_MIMETYPE_INFLATE = 64 * 1024;
const utf8Name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function zipName(bytes, flags) {
  if (flags & 0x800) return utf8Name.decode(bytes);
  // cp437: 0x00~0x7f는 ASCII. 그 위 바이트는 이름끼리 같은지만 보면 되므로 1:1 대응 글자로 둠
  let name = '';
  for (const byte of bytes) name += String.fromCharCode(byte < 0x80 ? byte : 0xf700 + byte);
  return name;
}

function zipEndRecord(buffer) {
  const size = buffer.length;
  let location;
  if (size >= 22 && buffer.readUInt32LE(size - 22) === 0x06054b50 && buffer[size - 2] === 0 && buffer[size - 1] === 0)
    location = size - 22;
  else {
    const start = buffer.lastIndexOf(EOCD_SIGNATURE);
    if (start < Math.max(size - 65536 - 22, 0) || start + 22 > size) return null;
    location = start;
  }
  const record = {
    location,
    sizeCd: buffer.readUInt32LE(location + 12),
    offsetCd: buffer.readUInt32LE(location + 16),
    zip64: false,
  };
  const locator = Math.max(location - 20, 0);
  if (buffer.readUInt32LE(locator) === 0x07064b50) {
    if (buffer.readUInt32LE(locator + 4) !== 0 || buffer.readUInt32LE(locator + 16) > 1)
      throw new Error('multi-disk zip');
    const end64 = Math.max(location - 76, 0);
    if (end64 + 56 <= size && buffer.readUInt32LE(end64) === 0x06064b50) {
      record.sizeCd = Number(buffer.readBigUInt64LE(end64 + 40));
      record.offsetCd = Number(buffer.readBigUInt64LE(end64 + 48));
      record.zip64 = true;
    }
  }
  return record;
}

function decodeZip64Extra(info, extra) {
  let rest = extra;
  while (rest.length >= 4) {
    const type = rest.readUInt16LE(0);
    const length = rest.readUInt16LE(2);
    if (length + 4 > rest.length) throw new Error('corrupt extra field');
    if (type === 1) {
      let field = rest.subarray(4, length + 4);
      for (const key of ['fileSize', 'compressSize', 'headerOffset']) {
        if (info[key] !== 0xffffffff) continue;
        if (field.length < 8) throw new Error('corrupt zip64 extra field');
        info[key] = Number(field.readBigUInt64LE(0));
        field = field.subarray(8);
      }
    }
    rest = rest.subarray(length + 4);
  }
}

function zipDirectory(buffer) {
  const end = zipEndRecord(buffer);
  if (!end) return null;
  const concat = end.location - end.sizeCd - end.offsetCd - (end.zip64 ? 76 : 0);
  const startDir = end.offsetCd + concat;
  if (startDir < 0) return null;
  const data = buffer.subarray(startDir, startDir + end.sizeCd);
  const entries = [];
  const byName = new Map();
  let total = 0;
  let at = 0;
  while (total < end.sizeCd) {
    if (at + 46 > data.length || data.readUInt32LE(at) !== 0x02014b50) return null;
    const flags = data.readUInt16LE(at + 8);
    const nameLength = data.readUInt16LE(at + 28);
    const extraLength = data.readUInt16LE(at + 30);
    const commentLength = data.readUInt16LE(at + 32);
    const info = {
      flags,
      method: data.readUInt16LE(at + 10),
      crc: data.readUInt32LE(at + 16),
      compressSize: data.readUInt32LE(at + 20),
      fileSize: data.readUInt32LE(at + 24),
      headerOffset: data.readUInt32LE(at + 42),
    };
    let next = at + 46;
    const nameBytes = data.subarray(next, next + nameLength);
    next += nameBytes.length;
    const extra = data.subarray(next, next + extraLength);
    next += extra.length;
    next += data.subarray(next, next + commentLength).length;
    info.origName = zipName(nameBytes, flags);
    if (data[at + 6] > 63) return null;
    decodeZip64Extra(info, extra);
    info.headerOffset += concat;
    const nul = info.origName.indexOf('\0');
    entries.push(info);
    byName.set(nul >= 0 ? info.origName.slice(0, nul) : info.origName, info);
    total += 46 + nameLength + extraLength + commentLength;
    at = next;
  }
  let endOffset = startDir;
  for (const info of [...entries].sort((a, b) => b.headerOffset - a.headerOffset)) {
    info.endOffset = endOffset;
    endOffset = info.headerOffset;
  }
  return byName;
}

function inflatePrefix(compressed, want, truncated) {
  let output;
  let ended = true;
  try {
    output = inflateRawSync(compressed, { maxOutputLength: MAX_MIMETYPE_INFLATE });
  } catch (error) {
    if (error?.code !== 'Z_BUF_ERROR') return null;
    ended = false;
    output = inflateRawSync(compressed, {
      finishFlush: zlibConstants.Z_SYNC_FLUSH,
      maxOutputLength: MAX_MIMETYPE_INFLATE,
    });
  }
  const value = output.subarray(0, want);
  return !ended && truncated && value.length < want ? null : value;
}

// zipfile.ZipFile.open(info).read(64): 지역 머리·이름 대조·겹침 검사·압축 해제·CRC 확인
function readSmallEntry(buffer, info) {
  const at = info.headerOffset;
  if (at < 0) return null;
  const head = buffer.subarray(at, at + 30);
  if (head.length !== 30 || head.readUInt32LE(0) !== 0x04034b50) return null;
  const nameBytes = buffer.subarray(at + 30, at + 30 + head.readUInt16LE(26));
  const extraStart = at + 30 + nameBytes.length;
  const extraBytes = buffer.subarray(extraStart, extraStart + head.readUInt16LE(28));
  if (info.flags & 0x60) return null;
  if (zipName(nameBytes, head.readUInt16LE(6)) !== info.origName) return null;
  const dataStart = extraStart + extraBytes.length;
  if (dataStart + info.compressSize > info.endOffset) return null;
  const compressed = buffer.subarray(dataStart, dataStart + info.compressSize);
  if (info.compressSize > 0 && compressed.length === 0) return null;
  let value;
  if (info.method === 0) {
    const need = Math.min(info.compressSize, info.fileSize);
    if (compressed.length < need) return null;
    value = compressed.subarray(0, need);
  } else if (info.method === 8) {
    value = info.compressSize === 0
      ? Buffer.alloc(0)
      : inflatePrefix(compressed, info.fileSize, compressed.length < info.compressSize);
    if (!value) return null;
  } else {
    return null;
  }
  return crc32(value) === info.crc ? value : null;
}

function pythonAsciiStrip(bytes) {
  let text = '';
  for (const byte of bytes) text += byte < 0x80 ? String.fromCharCode(byte) : '\ufffd';
  return text.replace(/^[\t\n\v\f\r\x1c-\x1f ]+|[\t\n\v\f\r\x1c-\x1f ]+$/g, '');
}

function zipIsHwpx(buffer) {
  const byName = zipDirectory(buffer);
  if (!byName) return false;
  const mimetype = byName.get('mimetype');
  if (mimetype) {
    if (mimetype.fileSize > 64 || mimetype.flags & 1) return false;
    const value = readSmallEntry(buffer, mimetype);
    return value !== null && pythonAsciiStrip(value) === HWPX_MIMETYPE;
  }
  return byName.has('Contents/content.hpf');
}
