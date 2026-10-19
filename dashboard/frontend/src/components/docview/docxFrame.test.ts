import { describe, expect, it } from 'vitest';
import { frameElementFactory } from './DocxFrame';

// 재설계 3h 보안(설계 6.6 '격리'): docx-preview가 만드는 요소를 격리 틀 문서에서 직접 만들고 위험한 것은 거른다.
// 실제 브라우저에서 외부 요청 0건·틀 CSP·sandbox 값은 stage3e/viewer-check.mjs가 확인한다.
function frameDocument() {
  return document.implementation.createHTMLDocument('frame');
}

describe('DOCX frame element factory', () => {
  it('creates elements in the frame document, not in the dashboard document', () => {
    const target = frameDocument();
    const h = frameElementFactory(target);
    const paragraph = h({ tagName: 'p', className: 'docx-p', style: 'color: red', children: ['본문 ', { tagName: 'span', children: ['굵게'] }] }) as HTMLElement;
    expect(paragraph.ownerDocument).toBe(target);
    expect(paragraph.outerHTML).toBe('<p class="docx-p" style="color: red">본문 <span>굵게</span></p>');
    const fromDashboard = document.createElement('b');
    expect((h(fromDashboard) as Node).ownerDocument).toBe(target);
  });

  it('drops script-capable elements and event handlers', () => {
    const h = frameElementFactory(frameDocument());
    for (const tagName of ['script', 'iframe', 'object', 'embed', 'link', 'meta', 'base', 'form']) expect((h({ tagName }) as Node).nodeType).toBe(Node.COMMENT_NODE);
    const svgScript = h({ ns: 'http://www.w3.org/2000/svg', tagName: 'script' }) as Node;
    expect(svgScript.nodeType).toBe(Node.COMMENT_NODE);
    const div = h({ tagName: 'div', onclick: 'alert(1)', onmouseover: () => undefined, innerHTML: '<img src=x onerror=alert(1)>' }) as HTMLElement;
    expect(div.outerHTML).toBe('<div></div>');
  });

  it('keeps only data: images and in-document links (outside addresses become a title only)', () => {
    const h = frameElementFactory(frameDocument());
    const outside = h({ tagName: 'img', src: 'http://198.51.100.7/track.png' }) as HTMLImageElement;
    expect(outside.getAttribute('src')).toBeNull();
    const inside = h({ tagName: 'img', src: 'data:image/png;base64,iVBORw0KGgo=' }) as HTMLImageElement;
    expect(inside.getAttribute('src')).toBe('data:image/png;base64,iVBORw0KGgo=');
    // docx-preview는 그림 주소를 나중에 넣는다(result.src = …) → 그때도 data: 그림만
    const later = h({ tagName: 'img' }) as HTMLImageElement;
    later.src = 'https://198.51.100.7/later.png';
    expect(later.getAttribute('src')).toBeNull();
    later.src = 'data:image/gif;base64,R0lGODlhAQABAAAAACw=';
    expect(later.getAttribute('src')).toBe('data:image/gif;base64,R0lGODlhAQABAAAAACw=');
    const link = h({ tagName: 'a', href: 'https://198.51.100.7/click', children: ['외부'] }) as HTMLAnchorElement;
    expect(link.hasAttribute('href')).toBe(false);
    expect(link.title).toBe('https://198.51.100.7/click');
    const bookmark = h({ tagName: 'a', href: '#section-2' }) as HTMLAnchorElement;
    expect(bookmark.getAttribute('href')).toBe('#section-2');
  });
});
