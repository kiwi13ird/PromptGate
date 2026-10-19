// 목록·상세 머리에 보이는 '일치 비율' 한 줄(2026-10-16 통일): 입력 중 문서와 같은 글자 비율(서버 same_text, 이벤트 상세 대조와 같은 원본).
// Detection 해시 근거 비율(score)은 '해시 근거 비율'로 따로 부른다(상세 세부 정보·탐지 기술).
import type { WindowHashDetection } from '@/src/types/event';
import { SAME_RATIO_NAME, formatSameRatio, ratioOf } from './matchRatio';

export const HASH_RATIO_NAME = '해시 근거 비율';

export function sameTextLabel(detection: WindowHashDetection): { value?: string; text: string; title: string } {
  const same = detection.sameText;
  if (same?.state === 'READY' && same.sameChars !== undefined && same.inputChars !== undefined) {
    const value = formatSameRatio(ratioOf(same.sameChars, same.inputChars));
    // 목록 칸이 좁은 폭(휴대폰 71px)에서 옛 글('94% 입력 일치 비율')처럼 두 줄 안에 들도록 이름 뒤에 값
    return { value, text: `${SAME_RATIO_NAME} ${value}`,
      title: `보낸 입력의 공백 뺀 ${same.inputChars.toLocaleString('ko-KR')}자 중 보호 문서와 같은 글자 ${same.sameChars.toLocaleString('ko-KR')}자${same.differences !== undefined ? ` · 다른 곳 ${same.differences.toLocaleString('ko-KR')}곳` : ''} (이벤트 상세 대조와 같은 계산)` };
  }
  if (same?.state === 'PENDING') return { text: '같은 글자 계산 중', title: '서버가 본문을 대조하는 중입니다. 다음 갱신에 채워집니다.' };
  if (same?.state === 'UNAVAILABLE') return { text: '같은 글자 대조 불가', title: `원문 대조 불가${same.reason ? ` · ${same.reason}` : ''}` };
  return { text: '같은 글자 확인 불가', title: '서버가 같은 글자 비율을 주지 않았습니다.' };
}
