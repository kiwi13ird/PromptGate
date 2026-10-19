import {describe,it,expect} from 'vitest';
import {formatProcessingTime,formatDurationSeconds,millisecondsToSeconds} from './format';
describe('consistent seconds display',()=>{
  it.each([[2974.1,'2.97초'],[8079.224,'8.08초'],[270.1,'0.27초'],[10,'0.01초'],[9.99,'0.01초 미만'],[0.3,'0.01초 미만'],[0,'0초'],[1000,'1초']])('formats %s milliseconds as %s',(input,label)=>{
    expect(formatProcessingTime(Number(input))).toBe(label);
  });
  it.each([undefined,NaN,Infinity,-1])('does not turn absent or invalid time %s into zero',input=>{
    expect(formatProcessingTime(input)).toBe('확인 불가');
    expect(formatDurationSeconds(input)).toBe('확인 불가');
    expect(millisecondsToSeconds(input)).toBeUndefined();
  });
  it('converts chart values without rounding or changing the original measurement',()=>{
    const raw=2974.1;expect(millisecondsToSeconds(raw)).toBe(2.9741);expect(raw).toBe(2974.1);
    expect(formatDurationSeconds(0.722)).toBe('0.72초');
  });
});
