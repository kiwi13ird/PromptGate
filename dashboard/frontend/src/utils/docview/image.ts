// 미리보기 그림 머리 확인(설계 6.3 HWP C안 "그림은 머리 확인 뒤 표시"): 파일 이름·확장자를 믿지 않고 첫 바이트로 형식·크기를 읽는다.
// 여기서 인정한 형식만 그린다(그 밖은 그림 없음으로 처리).
export type PreviewImageType = 'image/png' | 'image/gif' | 'image/bmp' | 'image/jpeg';

export interface PreviewImageInfo {
  type: PreviewImageType;
  width: number;
  height: number;
}

/** 가림 도구가 다시 쓴 HWP의 자리 표시 그림(64×64, 6.1 실측)과 그보다 작은 그림은 첫 쪽 그림으로 보지 않는다 */
export const PLACEHOLDER_MAX_EDGE = 64;

export function sniffImage(bytes: Uint8Array): PreviewImageInfo | null {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const has = (...values: number[]) => bytes.length >= values.length && values.every((value, index) => bytes[index] === value);
  if (has(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) && bytes.length >= 24) return { type: 'image/png', width: view.getUint32(16), height: view.getUint32(20) };
  if (has(0x47, 0x49, 0x46, 0x38) && bytes.length >= 10) return { type: 'image/gif', width: view.getUint16(6, true), height: view.getUint16(8, true) };
  if (has(0x42, 0x4d) && bytes.length >= 26) return { type: 'image/bmp', width: Math.abs(view.getInt32(18, true)), height: Math.abs(view.getInt32(22, true)) };
  if (has(0xff, 0xd8, 0xff)) {
    // SOF0~SOF15(C4·C8·CC 제외)에서 높이·폭
    let offset = 2;
    while (offset + 9 < bytes.length) {
      if (bytes[offset] !== 0xff) return null;
      const marker = bytes[offset + 1];
      const length = view.getUint16(offset + 2);
      if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) return { type: 'image/jpeg', width: view.getUint16(offset + 7), height: view.getUint16(offset + 5) };
      if (length < 2) return null;
      offset += 2 + length;
    }
    return null;
  }
  return null;
}

export function isPlaceholderImage(info: PreviewImageInfo) {
  return info.width <= PLACEHOLDER_MAX_EDGE && info.height <= PLACEHOLDER_MAX_EDGE;
}
