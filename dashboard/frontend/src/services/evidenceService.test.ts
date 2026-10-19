import { afterEach, describe, expect, it, vi } from 'vitest';
import { httpClient } from '@/src/api/httpClient';
import { evidenceService } from './evidenceService';

const base={event_id:'evt-a',source:'RDS_DECISION_LOG',coordinate_system:'NORMALIZED_UNICODE_CODE_POINTS',status:'AVAILABLE',comparisons:[]};
const page={status:'AVAILABLE',side:'input',document_id:'doc-a',char_start:0,char_end:3,total_chars:3,page_size:1800,segments:[{text:'가😀나',matched:true,redacted:false}],content_source:'RETAINED_INPUT'};
afterEach(()=>vi.restoreAllMocks());
describe('evidence response identity',()=>{
  it('rejects another event for both metadata and body',async()=>{
    vi.spyOn(httpClient,'get').mockResolvedValue({...base,event_id:'evt-b',page});
    await expect(evidenceService.getEventEvidence('evt-a')).rejects.toMatchObject({code:'INVALID_RESPONSE'});
    await expect(evidenceService.getPage('evt-a','input',0,'doc-a')).rejects.toMatchObject({code:'INVALID_RESPONSE'});
  });
  it.each([{side:'document'},{document_id:'doc-b'},{char_end:2},{content_source:'CURRENT_PROTECTED_DOCUMENT'}])('rejects mismatched body %j',async(change)=>{
    vi.spyOn(httpClient,'get').mockResolvedValue({...base,page:{...page,...change}});
    await expect(evidenceService.getPage('evt-a','input',0,'doc-a')).rejects.toMatchObject({code:'INVALID_RESPONSE'});
  });
  it('does not display a body attached to an unconfirmed join',async()=>{
    vi.spyOn(httpClient,'get').mockResolvedValue({...base,status:'MISMATCH',page});
    await expect(evidenceService.getPage('evt-a','input',0,'doc-a')).resolves.toEqual({status:'MISMATCH',side:'input'});
  });
  it('accepts normal unicode pages and the backend final-page clamp',async()=>{
    const get=vi.spyOn(httpClient,'get').mockResolvedValue({...base,page});
    await expect(evidenceService.getPage('evt-a','input',0,'doc-a')).resolves.toEqual(page);
    await expect(evidenceService.getPage('evt-a','input',1800,'doc-a')).resolves.toEqual(page);
    get.mockResolvedValue({...base,page:{...page,document_id:undefined}});
    await expect(evidenceService.getPage('evt-a','input',0)).resolves.toMatchObject({status:'AVAILABLE'});
  });
  it('accepts a verified protected document page',async()=>{
    vi.spyOn(httpClient,'get').mockResolvedValue({...base,page:{...page,side:'document',content_source:'EVENT_DOCUMENT_VERSION'}});
    await expect(evidenceService.getPage('evt-a','document',0,'doc-a')).resolves.toMatchObject({status:'AVAILABLE'});
  });
});
