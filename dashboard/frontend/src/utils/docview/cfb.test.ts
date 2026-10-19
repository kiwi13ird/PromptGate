import { describe, expect, it } from 'vitest';
import { CfbError, isCfb, readCfbStream } from './cfb';
import { isPlaceholderImage, sniffImage } from './image';

// 재설계 3h: HWP 5.0(복합 문서) 안 PrvImage 꺼내기 + 그림 머리 확인. 실제 HWP 견본(그림 있음·64×64·없음) 대조는 stage3e/viewer-check.mjs
const END = 0xfffffffe;
const FREE = 0xffffffff;

/** 512바이트 섹터·64바이트 작은 섹터의 작은 복합 문서: 작은 스트림 PrvImage(100B) + 큰 스트림 BigOne(5,000B) */
function buildCfb({ loop = false } = {}) {
  const small = Uint8Array.from({ length: 100 }, (_, i) => (i * 7) & 0xff);
  const big = Uint8Array.from({ length: 5000 }, (_, i) => (i * 13) & 0xff);
  const sectors = 4 + Math.ceil(big.length / 512);
  const bytes = new Uint8Array(512 * (sectors + 1));
  const view = new DataView(bytes.buffer);
  const at = (sector: number) => 512 * (sector + 1);
  [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].forEach((value, index) => { bytes[index] = value; });
  view.setUint16(0x18, 0x3e, true); view.setUint16(0x1a, 3, true); view.setUint16(0x1c, 0xfffe, true);
  view.setUint16(0x1e, 9, true); view.setUint16(0x20, 6, true);
  view.setUint32(0x2c, 1, true); view.setUint32(0x30, 1, true); view.setUint32(0x38, 4096, true);
  view.setUint32(0x3c, 2, true); view.setUint32(0x40, 1, true); view.setUint32(0x44, END, true); view.setUint32(0x48, 0, true);
  for (let i = 0; i < 109; i += 1) view.setUint32(0x4c + i * 4, i === 0 ? 0 : FREE, true);
  // FAT(섹터 0): 0 = FAT, 1 = 디렉터리, 2 = 작은 FAT, 3 = 작은 스트림, 4… = BigOne 사슬
  for (let i = 0; i < 128; i += 1) view.setUint32(at(0) + i * 4, FREE, true);
  view.setUint32(at(0), 0xfffffffd, true);
  view.setUint32(at(0) + 4, END, true);
  view.setUint32(at(0) + 8, END, true);
  view.setUint32(at(0) + 12, END, true);
  const bigSectors = Math.ceil(big.length / 512);
  for (let i = 0; i < bigSectors; i += 1) view.setUint32(at(0) + (4 + i) * 4, i === bigSectors - 1 ? (loop ? 4 : END) : 5 + i, true);
  // 디렉터리(섹터 1)
  const entry = (index: number, name: string, type: number, start: number, size: number) => {
    const base = at(1) + index * 128;
    [...name].forEach((char, i) => view.setUint16(base + i * 2, char.charCodeAt(0), true));
    view.setUint16(base + 0x40, (name.length + 1) * 2, true);
    bytes[base + 0x42] = type;
    view.setUint32(base + 0x74, start, true);
    view.setUint32(base + 0x78, size, true);
  };
  entry(0, 'Root Entry', 5, 3, 128);
  entry(1, 'PrvImage', 2, 0, small.length);
  entry(2, 'BigOne', 2, 4, big.length);
  // 작은 FAT(섹터 2): 작은 섹터 0 → 1 → 끝
  for (let i = 0; i < 128; i += 1) view.setUint32(at(2) + i * 4, FREE, true);
  view.setUint32(at(2), 1, true);
  view.setUint32(at(2) + 4, END, true);
  bytes.set(small, at(3));
  bytes.set(big, at(4));
  return { bytes, small, big };
}

describe('compound file (HWP 5.0) reader', () => {
  it('reads a small stream through the mini stream and a large stream through the FAT chain', () => {
    const { bytes, small, big } = buildCfb();
    expect(isCfb(bytes)).toBe(true);
    expect(readCfbStream(bytes, 'PrvImage')).toEqual(small);
    expect(readCfbStream(bytes, 'prvimage')).toEqual(small);
    expect(readCfbStream(bytes, 'BigOne')).toEqual(big);
    expect(readCfbStream(bytes, 'Missing')).toBeNull();
  });
  it('stops on broken chains, oversized streams and non-compound files', () => {
    expect(() => readCfbStream(buildCfb({ loop: true }).bytes, 'BigOne')).toThrow(CfbError);
    expect(() => readCfbStream(buildCfb().bytes, 'BigOne', 1000)).toThrow(CfbError);
    expect(() => readCfbStream(new TextEncoder().encode('PK\u0003\u0004 not a cfb'.padEnd(600, ' ')), 'PrvImage')).toThrow(CfbError);
    expect(isCfb(new Uint8Array(10))).toBe(false);
  });
});

describe('preview image header check', () => {
  const png = (width: number, height: number) => {
    const bytes = new Uint8Array(33);
    bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    new DataView(bytes.buffer).setUint32(16, width);
    new DataView(bytes.buffer).setUint32(20, height);
    return bytes;
  };
  it('reads type and size from the first bytes only', () => {
    expect(sniffImage(png(724, 1024))).toEqual({ type: 'image/png', width: 724, height: 1024 });
    const gif = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x10, 0x00, 0x20, 0x00]);
    expect(sniffImage(gif)).toEqual({ type: 'image/gif', width: 16, height: 32 });
    const bmp = new Uint8Array(30); bmp.set([0x42, 0x4d]); new DataView(bmp.buffer).setInt32(18, 300, true); new DataView(bmp.buffer).setInt32(22, -400, true);
    expect(sniffImage(bmp)).toEqual({ type: 'image/bmp', width: 300, height: 400 });
    const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x02, 0x00, 0x01, 0x80, 0x03]);
    expect(sniffImage(jpeg)).toEqual({ type: 'image/jpeg', width: 384, height: 512 });
    expect(sniffImage(new TextEncoder().encode('<svg onload=alert(1)>'))).toBeNull();
  });
  it('treats the 64×64 placeholder written by the masking tool as no preview', () => {
    expect(isPlaceholderImage({ type: 'image/png', width: 64, height: 64 })).toBe(true);
    expect(isPlaceholderImage({ type: 'image/png', width: 724, height: 1024 })).toBe(false);
  });
});
