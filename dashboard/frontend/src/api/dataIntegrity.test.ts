import {describe,it,expect} from 'vitest';
import {mapDashboardStatsDto,mapSecurityEventDto,mapTrafficSnapshotDto,mapPolicyDto} from './mappers';
import {trafficTimeBucketSchema} from './schemas';
import type {DashboardStatsDto,SecurityEventDto,DetectionPolicyDto} from './dto';

const event:SecurityEventDto={event_id:'isolated-event',occurred_at:'2026-10-03T15:00:00Z',client_id:'isolated',target_llm:'Gemini',action:'ALLOW',status:'NEW',detections:[],admin_notes:[],timeline:[]};
describe('missing API data stays missing rather than becoming operational facts',()=>{
 it('does not manufacture NO_MATCH or enforcement from an ALLOW record',()=>{const result=mapSecurityEventDto(event);expect(result.detectionOutcome).toBe('UNAVAILABLE');expect(result.enforcement).toBeUndefined();expect(result.policyVersion).toBeUndefined();});
 it('distinguishes absent aggregates from recorded zero',()=>{const raw:DashboardStatsDto={total:0,block:0,mask:0,new_events:0,average_processing_ms:0,trend:[],recent:[]};const result=mapDashboardStatsDto(raw);expect(result.allow).toBeUndefined();expect(result.degraded).toBeUndefined();expect(result.enforcementRate).toBeUndefined();expect(result.actionMismatch).toBeUndefined();expect(mapDashboardStatsDto({...raw,allow:0}).allow).toBe(0);});
 it('does not invent real-time metrics, benchmark records or audit history',()=>{const result=mapTrafficSnapshotDto({summary:{},time_series:[]},'30D');expect(result.summary.concurrentRequests).toBeUndefined();expect(result.summary.averageLatencyMs).toBeUndefined();expect('performanceRuns' in result).toBe(false);});
 it('leaves missing policy scope and history unknown',()=>{const raw:DetectionPolicyDto={policy_id:'isolated-policy',detector:'SIGNATURE',detection_target:'PII',action:'MASK',version:1,enabled:true};const result=mapPolicyDto(raw);expect(result.targetLlms).toEqual([]);expect(result.documentClassification).toBeUndefined();expect(result.versions).toEqual([]);});
 it('rejects malformed time and inconsistent action sums instead of charting them',()=>{const raw={timestamp:'2026-10-03T00:00:00Z',request_count:2,block_count:1,mask_count:1,allow_count:0};expect(trafficTimeBucketSchema.safeParse(raw).success).toBe(true);expect(trafficTimeBucketSchema.safeParse({...raw,timestamp:'not-a-date'}).success).toBe(false);expect(trafficTimeBucketSchema.safeParse({...raw,allow_count:1}).success).toBe(false);});
});
