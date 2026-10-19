// 복합 문서(CFB, MS-CFB) 읽기 — HWP 5.0 파일 안의 스트림 하나(PrvImage, 첫 쪽 미리보기 그림)만 꺼낸다(설계 6.3 HWP C안).
// 쓰기·수정·압축 해제는 하지 않는다. 범위를 벗어나는 값·끝나지 않는 사슬은 오류로 멈춘다(깨진 파일·악성 파일 대비).
const SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END_OF_CHAIN = 0xfffffffe;
const FREE_SECTOR = 0xffffffff;
const NO_STREAM = 0xffffffff;
const HEADER_DIFAT_ENTRIES = 109;

export class CfbError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CfbError';
  }
}

export function isCfb(bytes: Uint8Array) {
  return bytes.length >= 512 && SIGNATURE.every((value, index) => bytes[index] === value);
}

interface DirectoryEntry {
  name: string;
  type: number;
  start: number;
  size: number;
}

/** name과 같은 이름의 스트림(대소문자 무시)을 찾아 바이트를 돌려준다. 없으면 null. maxBytes보다 크면 오류 */
export function readCfbStream(bytes: Uint8Array, name: string, maxBytes = 8 * 1024 * 1024): Uint8Array | null {
  if (!isCfb(bytes)) throw new CfbError('복합 문서 머리가 아님');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (offset: number) => view.getUint16(offset, true);
  const u32 = (offset: number) => view.getUint32(offset, true);
  if (u16(0x1c) !== 0xfffe) throw new CfbError('바이트 순서 표시가 다름');
  const sectorShift = u16(0x1e);
  const miniShift = u16(0x20);
  if (sectorShift !== 9 && sectorShift !== 12) throw new CfbError('지원하지 않는 섹터 크기');
  if (miniShift !== 6) throw new CfbError('지원하지 않는 작은 섹터 크기');
  const sectorSize = 1 << sectorShift;
  const miniSize = 1 << miniShift;
  const sectorCount = Math.max(0, Math.ceil((bytes.length - sectorSize) / sectorSize));
  const fatSectors = u32(0x2c);
  const firstDir = u32(0x30);
  const miniCutoff = u32(0x38);
  const firstMiniFat = u32(0x3c);
  const miniFatSectors = u32(0x40);
  let difatSector = u32(0x44);
  const difatSectors = u32(0x48);
  if (fatSectors > sectorCount || miniFatSectors > sectorCount || difatSectors > sectorCount) throw new CfbError('섹터 수가 파일보다 큼');

  const sectorOffset = (sector: number) => {
    const offset = (sector + 1) * sectorSize;
    if (sector >= sectorCount || offset >= bytes.length) throw new CfbError('섹터 번호가 범위를 벗어남');
    return offset;
  };
  const readSector = (sector: number) => {
    const offset = sectorOffset(sector);
    return bytes.subarray(offset, Math.min(bytes.length, offset + sectorSize));
  };

  // FAT 섹터 목록(DIFAT): 머리 109개 + DIFAT 사슬
  const fatList: number[] = [];
  for (let index = 0; index < HEADER_DIFAT_ENTRIES && fatList.length < fatSectors; index += 1) {
    const sector = u32(0x4c + index * 4);
    if (sector !== FREE_SECTOR) fatList.push(sector);
  }
  for (let hops = 0; fatList.length < fatSectors && difatSector !== END_OF_CHAIN && difatSector !== FREE_SECTOR; hops += 1) {
    if (hops > difatSectors) throw new CfbError('DIFAT 사슬이 끝나지 않음');
    const offset = sectorOffset(difatSector);
    const perSector = sectorSize / 4 - 1;
    for (let index = 0; index < perSector && fatList.length < fatSectors; index += 1) {
      const sector = view.getUint32(offset + index * 4, true);
      if (sector !== FREE_SECTOR) fatList.push(sector);
    }
    difatSector = view.getUint32(offset + perSector * 4, true);
  }
  const fat = new Uint32Array(fatList.length * (sectorSize / 4));
  fatList.forEach((sector, index) => {
    const offset = sectorOffset(sector);
    for (let entry = 0; entry < sectorSize / 4; entry += 1) fat[index * (sectorSize / 4) + entry] = view.getUint32(offset + entry * 4, true);
  });

  // 사슬을 따라 읽기(같은 섹터를 두 번 지나면 고리 → 오류)
  const chain = (start: number, table: Uint32Array, limit: number) => {
    const sectors: number[] = [];
    const seen = new Set<number>();
    for (let sector = start; sector !== END_OF_CHAIN; sector = table[sector]) {
      if (sector === FREE_SECTOR || sector >= table.length || seen.has(sector) || sectors.length > limit) throw new CfbError('섹터 사슬이 깨짐');
      seen.add(sector);
      sectors.push(sector);
    }
    return sectors;
  };
  const readChain = (start: number, size?: number) => {
    const sectors = chain(start, fat, sectorCount);
    const out = new Uint8Array(sectors.length * sectorSize);
    sectors.forEach((sector, index) => out.set(readSector(sector), index * sectorSize));
    return size === undefined ? out : out.subarray(0, Math.min(size, out.length));
  };

  // 디렉터리(128바이트 항목)
  const directory = readChain(firstDir);
  const entries: DirectoryEntry[] = [];
  const dirView = new DataView(directory.buffer, directory.byteOffset, directory.byteLength);
  for (let offset = 0; offset + 128 <= directory.length; offset += 128) {
    const nameBytes = Math.min(64, dirView.getUint16(offset + 0x40, true));
    let entryName = '';
    for (let index = 0; index + 1 < nameBytes - 1; index += 2) entryName += String.fromCharCode(dirView.getUint16(offset + index, true));
    entries.push({ name: entryName, type: directory[offset + 0x42], start: dirView.getUint32(offset + 0x74, true), size: dirView.getUint32(offset + 0x78, true) });
  }
  const root = entries[0];
  if (!root || root.type !== 5) throw new CfbError('뿌리 항목이 없음');
  const target = entries.find((entry) => entry.type === 2 && entry.name.toLowerCase() === name.toLowerCase());
  if (!target) return null;
  if (target.size > maxBytes) throw new CfbError('스트림이 너무 큼');
  if (target.size === 0 || target.start === NO_STREAM) return new Uint8Array(0);

  if (target.size >= miniCutoff) return readChain(target.start, target.size).slice();

  // 작은 스트림: 뿌리 항목의 작은 스트림 안에서 작은 FAT 사슬을 따른다
  const miniStream = readChain(root.start, root.size);
  const miniFatBytes = firstMiniFat === END_OF_CHAIN ? new Uint8Array(0) : readChain(firstMiniFat);
  const miniFat = new Uint32Array(miniFatBytes.length / 4);
  const miniFatView = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength);
  for (let index = 0; index < miniFat.length; index += 1) miniFat[index] = miniFatView.getUint32(index * 4, true);
  const sectors = chain(target.start, miniFat, Math.ceil(miniStream.length / miniSize));
  const out = new Uint8Array(sectors.length * miniSize);
  sectors.forEach((sector, index) => {
    const offset = sector * miniSize;
    if (offset + miniSize > miniStream.length) throw new CfbError('작은 섹터가 범위를 벗어남');
    out.set(miniStream.subarray(offset, offset + miniSize), index * miniSize);
  });
  return out.slice(0, target.size);
}
