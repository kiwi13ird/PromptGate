import { describe, expect, it } from 'vitest';
import { scanExtensionFiles } from '../../scripts/check-extension-csp.mjs';

// 확장 프로그램 번들 MV3 CSP 정적 점검 규칙(가짜 파일로 확인)
const html = (body: string, head = '') =>
  `<!doctype html><html><head>${head}<link rel="stylesheet" href="./assets/a.css"></head><body><div id="root"></div>${body}</body></html>`;
const clean = [
  { path: 'myrequests.html', text: html('<script type="module" src="./assets/myrequests-abc.js"></script>',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src http://llm-gateway.local">`) },
  { path: 'assets/myrequests-abc.js', text: 'const f=Function.prototype.toString;const u=`https://react.dev/errors/`;o.innerHTML=`<script><\\/script>`;fetch(new URL(`requests`,b));' },
  { path: 'assets/a.css', text: '.x{background:url(./i.png)}.y{background:url("data:image/svg+xml,%3Csvg%3E")}' },
  { path: 'assets/i.png' },
];
const scan = (replace: Record<string, string>) => scanExtensionFiles(clean.map(file => (file.path in replace ? { ...file, text: replace[file.path] } : file)));

describe('확장 프로그램 번들 CSP 점검', () => {
  it('외부 모듈 스크립트·상대 경로·Function.prototype 접근만 있는 번들은 통과', () => {
    expect(scanExtensionFiles(clean)).toEqual([]);
  });

  it('인라인 스크립트·이벤트 속성·절대 경로·data: 스크립트·unsafe CSP를 잡는다', () => {
    const cases: [string, RegExp][] = [
      [html('<script>alert(1)</script>'), /인라인 스크립트/],
      [html('<script type="module" src="./a.js">x()</script>'), /스크립트 태그 안에 코드/],
      [html('<script src="data:text/javascript,alert(1)"></script>'), /상대 경로가 아닌 스크립트/],
      [html('<script src="https://cdn.example.com/a.js"></script>'), /상대 경로가 아닌 스크립트/],
      [html('<script src="/assets/a.js"></script>'), /상대 경로가 아닌 스크립트|루트 절대 경로/],
      [html('<button onclick="go()">x</button>'), /on\* 인라인 이벤트/],
      [html('<a href="javascript:go()">x</a>'), /javascript:/],
      [html('<iframe src="./x.html"></iframe>'), /iframe/],
      [html('', `<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-eval'">`), /unsafe/],
      [html('<script type="module" src="./a.js">'), /닫히지 않은/],
    ];
    for (const [text, expected] of cases) expect(scan({ 'myrequests.html': text }).join('\n'), text).toMatch(expected);
  });

  it('eval·new Function·Function 생성자 별칭·문자열 타이머·data: 스크립트를 잡는다', () => {
    const cases: [string, RegExp][] = [
      ['x=eval("1+1")', /eval\(/],
      ['x=(0,eval)("1")', /간접 eval/],
      ['x=new Function("a","return a")', /new Function/],
      ['try{return Function(``),!0}catch{return!1}', /Function\( 생성자/],
      ['compile(){let e=Function,t=this.c;return new e(...t)}', /Function 생성자 별칭/],
      ['setTimeout("go()",10)', /문자열 setTimeout/],
      ['s.src="data:text/javascript;base64,YWxlcnQoMSk="', /data: 스크립트/],
      ['import(`https://cdn.example.com/m.js`)', /동적 import|외부 스크립트/],
      ['//# sourceMappingURL=a.js.map', /sourcemap/],
    ];
    for (const [text, expected] of cases) expect(scan({ 'assets/myrequests-abc.js': text }).join('\n'), text).toMatch(expected);
  });

  it('CSS의 외부·루트 절대 경로·@import와 허용하지 않는 파일을 잡는다', () => {
    expect(scan({ 'assets/a.css': '@import url(./b.css);' }).join('\n')).toMatch(/@import/);
    expect(scan({ 'assets/a.css': '.x{background:url(https://example.com/a.png)}' }).join('\n')).toMatch(/외부·루트 절대 경로/);
    expect(scan({ 'assets/a.css': '.x{background:url(/a.png)}' }).join('\n')).toMatch(/외부·루트 절대 경로/);
    expect(scanExtensionFiles([...clean, { path: 'assets/a.js.map', text: '{}' }]).join('\n')).toMatch(/sourcemap 파일/);
    expect(scanExtensionFiles([...clean, { path: 'assets/run.wasm' }]).join('\n')).toMatch(/허용하지 않는 파일/);
    expect(scanExtensionFiles(clean.filter(file => !file.path.endsWith('.html')))).toContain('HTML 파일이 없음');
  });
});
