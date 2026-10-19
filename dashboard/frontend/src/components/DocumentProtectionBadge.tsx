import type {ConfidentialDocument} from '@/src/types/policy';
import {documentProtectionStage} from '@/src/utils/documentPresentation';
import {PgBadge} from '@/src/components/pg';

// 보호 상태 배지(재설계 2단계): 새 배지 1종(설계 4.4). 글자 → 계열은 배지 표(badgeTone.ts)가 정한다
// (보호 중 = 정상 · 분석 중 = 진행 · 분석 실패 = 차단 · 준비 확인 필요 = 주의 · 보호 중지 = 중립). 보호 문서 목록·상세만 쓴다(이벤트 화면 밖).
export function DocumentProtectionBadge({document}:{document:ConfidentialDocument}) {
  const stage=documentProtectionStage(document);
  // 옛 클래스(document-protection-badge·protection-*)는 옛 규칙(.console-shell .document-protection-badge 0,2,0)이 배지 모양을 지워서 달지 않는다(시험이 쓰지 않음)
  return <PgBadge value={stage.label} title={stage.detail}/>;
}
