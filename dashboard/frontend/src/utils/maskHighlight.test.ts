import {describe,it,expect} from 'vitest';
import {maskHighlights,splitHighlightedText} from './maskHighlight';
import type {EventEvidence} from '@/src/services/evidenceService';
type Proof=NonNullable<EventEvidence['mask_comparison']>;
function proof(before:string,after:string,spans:Proof['spans']):Proof{return {status:'REQUEST_REWRITTEN',entity_counts:[],before_preview:before,after_preview:after,before_chars:Array.from(before).length,after_chars:Array.from(after).length,preview_truncated:false,spans};}
describe('recorded mask alignment',()=>{
  it('uses Unicode coordinates and variable replacement lengths',()=>{
    const result=maskHighlights(proof('😀 앞 ███ 중간 ██ 끝','😀 앞 [PHONE] 중간 * 끝',[{start:4,end:7,entityType:'PHONE'},{start:11,end:13,entityType:'KEY'}]));
    expect(result).toEqual({before:[{start:4,end:7},{start:11,end:13}],after:[{start:4,end:11},{start:15,end:16}],mapped:true});
    expect(splitHighlightedText('😀 앞 [PHONE] 중간 * 끝',result.after).filter(p=>p.highlighted).map(p=>p.text)).toEqual(['[PHONE]','*']);
  });
  it('does not infer positions from mask token names',()=>{
    expect(maskHighlights(proof('앞 ██ 끝','앞 secret-token 끝',[{start:2,end:4,entityType:'X'}])).after).toEqual([{start:2,end:14}]);
  });
  it('merges overlapping recorded ranges',()=>{
    expect(maskHighlights(proof('a████z','a***z',[{start:1,end:4,entityType:'X'},{start:3,end:5,entityType:'Y'}])).after).toEqual([{start:1,end:4}]);
  });
  it('refuses truncated, missing or invalid span evidence',()=>{
    const value=proof('a██z','a***z',[{start:1,end:3,entityType:'X'}]);
    for(const patch of [{preview_truncated:true},{before_chars:50},{after_chars:50},{spans:[]},{spans:[{start:1,end:90,entityType:'X'}]}])expect(maskHighlights({...value,...patch}).mapped).toBe(false);
  });
  it('refuses ambiguous outside context or changes outside recorded ranges',()=>{
    expect(maskHighlights(proof('a██ end','aX end end',[{start:1,end:3,entityType:'X'}])).after).toEqual([]);
    expect(maskHighlights(proof('a██z','b***z',[{start:1,end:3,entityType:'X'}])).mapped).toBe(false);
  });
  it('handles empty replacements and end-of-text ranges',()=>{
    expect(maskHighlights(proof('a██','a',[{start:1,end:3,entityType:'X'}]))).toMatchObject({mapped:true,after:[]});
  });
});
