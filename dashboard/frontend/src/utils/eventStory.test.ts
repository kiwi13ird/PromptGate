import { describe, expect, it } from 'vitest';
import { eventStory } from './eventStory';
import type { SecurityEvent, WindowHashDetection } from '@/src/types/event';
const match:WindowHashDetection={detector:'WINDOW_HASH',matchType:'TEXT_FRAGMENT',score:0.97,scoreKind:'COVERAGE',matchedDocumentId:'doc-1',matchedDocumentName:'공정 보고서',documentSpan:{charStart:10,charEnd:80,endExclusive:true}};
const base:SecurityEvent={eventId:'evt-1',occurredAt:'2026-10-01T10:00:00Z',clientId:'test',targetLlm:'ChatGPT',detectionOutcome:'MATCH',finalAction:'BLOCK',status:'NEW',detections:[match],adminNotes:[],timeline:[]};
describe('record-based event story',()=>{
  it('does not claim execution from the final action alone',()=>{
    const story=eventStory(base);
    expect(story.reason).toContain('공정 보고서');
    expect(story.final).toBe('최종 조치는 차단입니다.');
    expect(story.enforcement).toContain('확인 기록이 없습니다');
    expect(eventStory({...base,enforcement:{applied:true,httpStatus:403}}).enforcement).toContain('집행 확인 기록');
    expect(eventStory({...base,enforcement:{applied:false}}).enforcement).toContain('집행되지 않은');
  });
  it('does not confuse unavailable with a safe no-match result',()=>{
    expect(eventStory({...base,detectionOutcome:'UNAVAILABLE',detections:[],finalAction:'ALLOW'}).reason).toBe('탐지 결과를 확인할 수 없습니다.');
    expect(eventStory({...base,detectionOutcome:'NO_MATCH',detections:[]}).reason).toContain('없습니다');
    expect(eventStory({...base,detectionOutcome:'NO_MATCH',detections:[],degraded:true,finalAction:'ALLOW'}).reason).toBe('탐지 결과를 확인할 수 없습니다.');
  });
  it('deduplicates document IDs and does not expose one score as a combined match percentage',()=>{
    const story=eventStory({...base,detections:[match,match,{...match,matchedDocumentId:'doc-2'}]});
    expect(story.documents).toHaveLength(2);
    expect(story.reason).toContain('보호 문서 2개');   // 2026-10-16 문서 수는 '개'
  });
  it('does not describe intentionally allowed traffic as a failed block',()=>{
    expect(eventStory({...base,finalAction:'ALLOW',enforcement:{applied:false}}).enforcement).toContain('추가 차단·치환을 적용하지 않은');
  });
});
