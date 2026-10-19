import type { EventEvidence } from '@/src/services/evidenceService';
export type TextRange={start:number;end:number};
type Proof=NonNullable<EventEvidence['mask_comparison']>;

// Coordinates are Unicode code points. Do not guess replacement lengths or
// search for mask tokens: only align recorded spans with unchanged context.
export function maskHighlights(proof: Proof) {
  const before=Array.from(proof.before_preview??''),after=Array.from(proof.after_preview??'');
  const spans=(proof.spans??[]).filter(s=>Number.isInteger(s.start)&&Number.isInteger(s.end)&&s.start>=0&&s.end>s.start&&s.end<=before.length).sort((a,b)=>a.start-b.start);
  const ranges:TextRange[]=[];
  for(const span of spans){const last=ranges.at(-1);if(last&&span.start<=last.end)last.end=Math.max(last.end,span.end);else ranges.push({start:span.start,end:span.end});}
  const unavailable={before:ranges,after:[] as TextRange[],mapped:false};
  if(proof.status!=='REQUEST_REWRITTEN'||proof.preview_truncated||!ranges.length||before.length!==proof.before_chars||after.length!==proof.after_chars)return unavailable;
  // A span outside the retained preview prevents full alignment, not just that highlight.
  if(spans.length!==(proof.spans??[]).length)return unavailable;
  let left=0,right=0;
  const mapped:TextRange[]=[];
  for(let index=0;index<ranges.length;index++){
    const span=ranges[index],prefix=before.slice(left,span.start).join('');
    if(after.slice(right,right+Array.from(prefix).length).join('')!==prefix)return unavailable;
    right+=Array.from(prefix).length;
    const suffix=before.slice(span.end,ranges[index+1]?.start??before.length).join('');
    let stop=after.length;
    if(suffix){
      const remaining=after.slice(right).join(''),at=remaining.indexOf(suffix);
      if(at<0||remaining.indexOf(suffix,at+1)>=0)return unavailable;
      stop=right+Array.from(remaining.slice(0,at)).length;
    }
    mapped.push({start:right,end:stop});right=stop;left=span.end;
  }
  if(before.slice(left).join('')!==after.slice(right).join(''))return unavailable;
  return {before:ranges,after:mapped.filter(s=>s.end>s.start),mapped:true};
}

export function splitHighlightedText(text:string,ranges:TextRange[]) {
  const chars=Array.from(text),edges=[...new Set([0,chars.length,...ranges.flatMap(s=>[Math.max(0,Math.min(chars.length,s.start)),Math.max(0,Math.min(chars.length,s.end))])])].sort((a,b)=>a-b);
  return edges.slice(0,-1).map((start,index)=>({text:chars.slice(start,edges[index+1]).join(''),highlighted:ranges.some(s=>s.start<=start&&s.end>=edges[index+1])}));
}
