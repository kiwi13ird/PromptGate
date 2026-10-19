import type {ConfidentialDocument} from '@/src/types/policy';

export function documentProtectionStage(document:ConfidentialDocument) {
  const indexes=document.activeDetectors.flatMap(detector=>detector==='WINDOW_HASH'?[document.chunkIndexStatus]:detector==='SHA256'?[document.exactFingerprintStatus]:detector==='MINHASH'?[document.similarityFingerprintStatus]:[]);
  if(document.status==='INACTIVE')return {label:'보호 중지',tone:'neutral',detail:'보호 설정이 꺼져 있습니다. 등록 기록은 유지됩니다.'};
  if(document.processingStatus==='FAILED'||indexes.includes('FAILED'))return {label:'분석 실패',tone:'danger',detail:'분석 또는 색인 실패가 기록됐습니다. 보호 설정이 켜져 있어도 준비 완료는 아닙니다.'};
  if(document.processingStatus==='PROCESSING'||indexes.includes('PROCESSING'))return {label:'분석 중',tone:'pending',detail:'등록됐으며 분석·색인 완료를 기다리고 있습니다.'};
  if(document.processingStatus==='READY'&&document.activeDetectors.length>0&&indexes.every(status=>status==='READY'))return {label:'보호 중',tone:'ready',detail:'서버 기록상 분석·색인이 준비됐으며 보호 설정이 켜져 있습니다.'};
  return {label:'준비 확인 필요',tone:'pending',detail:'등록돼 있지만 사용할 탐지 방식이나 색인 준비 상태를 확인하지 못했습니다.'};
}
