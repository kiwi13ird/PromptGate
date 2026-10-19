import {describe,it,expect} from 'vitest';
import {documentProtectionStage} from './documentPresentation';
import type {ConfidentialDocument} from '@/src/types/policy';
const document:ConfidentialDocument={documentId:'doc-1',documentName:'공정',registeredAt:'2026-10-01T00:00:00Z',status:'ACTIVE',processingStatus:'READY',fileType:'PDF',chunkCount:1,chunkIndexStatus:'READY',exactFingerprintStatus:'NOT_AVAILABLE',similarityFingerprintStatus:'NOT_AVAILABLE',activeDetectors:['WINDOW_HASH']};
describe('document preparation is not protection configuration alone',()=>{
  it('shows protection only when configured indexes are ready',()=>expect(documentProtectionStage(document).label).toBe('보호 중'));
  it('keeps inactive documents stopped even if their indexes are ready',()=>expect(documentProtectionStage({...document,status:'INACTIVE'}).label).toBe('보호 중지'));
  it('distinguishes registered from still processing',()=>expect(documentProtectionStage({...document,processingStatus:'PROCESSING'}).label).toBe('분석 중'));
  it('does not call a failed index protected',()=>expect(documentProtectionStage({...document,chunkIndexStatus:'FAILED'}).label).toBe('분석 실패'));
  it('does not call an unavailable index protected',()=>expect(documentProtectionStage({...document,chunkIndexStatus:'NOT_AVAILABLE'}).label).toBe('준비 확인 필요'));
  it('does not invent protection without configured detectors',()=>expect(documentProtectionStage({...document,activeDetectors:[]}).label).toBe('준비 확인 필요'));
  it('checks all configured fingerprint types',()=>{
    expect(documentProtectionStage({...document,activeDetectors:['SHA256']}).label).toBe('준비 확인 필요');
    expect(documentProtectionStage({...document,activeDetectors:['MINHASH'],similarityFingerprintStatus:'FAILED'}).label).toBe('분석 실패');
  });
});
