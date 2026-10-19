import type { SecurityEvent } from '@/src/types/event';
import { inspectionFailure } from './eventPresentation';
import { formatCount } from '@/src/utils/format';

export const storyPercent = (value: number) => `${(value * 100).toLocaleString('ko-KR', { maximumFractionDigits: 1 })}%`;

export function eventStory(event: SecurityEvent) {
  const documents = [...new Map(event.detections.flatMap(detection => 'matchedDocumentId' in detection ? [[detection.matchedDocumentId, detection.matchedDocumentName ?? detection.matchedDocumentId] as const] : [])).entries()];
  const document = documents.length === 1 ? `‘${documents[0][1]}’` : documents.length > 1 ? `보호 문서 ${formatCount(documents.length)}개` : '보호 문서';
  const final = event.finalAction === 'BLOCK' ? '최종 조치는 차단입니다.' : event.finalAction === 'MASK' ? '최종 조치는 마스킹입니다.' : '최종 조치는 허용입니다.';
  let reason: string;
  const failure = inspectionFailure(event);
  if (failure && 'accessBlock' in failure) reason = '관리자 설정에 따라 접속 단계에서 차단했습니다. 내용은 검사하지 않았습니다.';
  else if (failure) reason = '탐지 결과를 확인할 수 없습니다.';
  else if (event.detectionOutcome === 'NO_MATCH') reason = '일치한 보호 문서나 민감정보가 없습니다.';
  else if (documents.length) reason = `보내려던 내용에서 ${document}와의 일치가 탐지됐습니다.`;
  else if (event.detections.some(item => item.detector === 'SIGNATURE')) reason = '보내려던 내용에서 민감정보가 탐지됐습니다.';
  else reason = '탐지는 기록됐지만 상세 근거가 없습니다.';
  const enforcement = event.enforcement === undefined ? '실제 집행 여부는 당시 확인 기록이 없습니다.' : event.enforcement.applied ? '게이트웨이 집행 확인 기록이 있습니다.' : event.finalAction === 'ALLOW' ? '추가 차단·치환을 적용하지 않은 기록입니다.' : '집행되지 않은 것으로 기록됐습니다.';
  return { documents, reason, final, enforcement };
}
