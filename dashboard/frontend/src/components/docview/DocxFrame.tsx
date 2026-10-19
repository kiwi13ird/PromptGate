// DOCX 본문 모양(설계 6.3 DOCX A안): docx-preview 0.4.1로 문단·표·그림·머리말을 그린다. 본문 보기를 열 때만 불러온다(동적 import).
// 보안(설계 6.6 '격리'):
//  1) 결과는 스크립트를 못 돌리는 격리 틀(iframe sandbox="allow-same-origin", allow-scripts 없음) 안에만 그린다.
//  2) 틀 안 CSP: default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data: → 문서 안 외부 그림·글꼴 주소로 요청이 나가지 않는다.
//  3) 요소는 docx-preview의 h 옵션으로 틀 문서에서 직접 만든다(바깥 문서에서 만들어 옮기지 않음 → 만들 때부터 틀 CSP 적용).
//     만들면서 걸러 낸다: script·iframe·object·embed·link·meta·base·form 등은 만들지 않고, on* 속성은 버리고,
//     src는 data: 그림만, href는 문서 안 이동(#…)만 남긴다(바깥 주소는 title로만 보임).
//  4) altChunk(문서에 끼운 HTML 조각)는 그리지 않는다(renderAltChunks: false). 그림·글꼴은 data: 주소(useBase64URL)로 → 닫으면 틀과 함께 사라진다.
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { renderAsync } from 'docx-preview';
import { FIRST_PAINT_TIMEOUT_MS, failureReason, type RendererProps } from './types';

const FRAME_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:";
// 틀 바탕은 뷰어 바탕(회색) 위 흰 쪽 그대로. docx-preview 기본 회색 바탕·여백은 지운다
const FRAME_BASE_CSS = [
  'html,body{margin:0;padding:0;background:transparent;}',
  '.docx-wrapper{background:transparent!important;padding:16px 0 8px!important;display:flex;flex-flow:column;align-items:center;}',
  '.docx-wrapper>section.docx{box-shadow:0 1px 3px rgba(0,0,0,.18)!important;margin:0 0 16px!important;}',
].join('');
const FRAME_DOC = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}"><style>${FRAME_BASE_CSS}</style><style id="pg-zoom"></style></head><body><div id="pg-docx-styles"></div><div id="pg-docx-body"></div></body></html>`;

const BLOCKED_TAGS = new Set(['script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'link', 'meta', 'base', 'form', 'input', 'button', 'textarea', 'select', 'video', 'audio', 'source', 'track', 'portal', 'noscript', 'template']);
const SVG_NS = 'http://www.w3.org/2000/svg';

type HNode = string | Node | { ns?: string; tagName: string; className?: string; style?: string | Record<string, string>; children?: HNode[]; [key: string]: unknown };

// 다른 문서(바깥 화면)에서 만든 노드도 Node로 본다(틀 문서와 바깥 문서의 Node 생성자가 다르다)
const isDomNode = (value: unknown): value is Node => typeof value === 'object' && value !== null && typeof (value as Node).nodeType === 'number' && typeof (value as Node).cloneNode === 'function';

/** docx-preview의 요소 만들기(h)를 틀 문서용 + 거르기로 바꾼 것 */
export function frameElementFactory(target: Document) {
  const make = (node: HNode): Node => {
    if (typeof node === 'string') return target.createTextNode(node);
    if (isDomNode(node)) return node.ownerDocument === target ? node : target.adoptNode(node);
    const { ns, tagName, className, style, children, ...props } = node as Exclude<HNode, string | Node>;
    if (tagName === '#fragment') {
      const fragment = target.createDocumentFragment();
      children?.forEach((child) => fragment.appendChild(make(child)));
      return fragment;
    }
    if (tagName === '#comment') return target.createComment(typeof children?.[0] === 'string' ? children[0] : '');
    const lower = tagName.toLowerCase();
    if (BLOCKED_TAGS.has(lower) || (ns === SVG_NS && ['script', 'foreignobject', 'a', 'use', 'image', 'animate', 'set'].includes(lower))) return target.createComment('blocked');
    const element = ns ? target.createElementNS(ns, tagName) : target.createElement(tagName);
    if (className) element.setAttribute('class', String(className));
    if (style) {
      if (typeof style === 'string') element.setAttribute('style', style);
      else Object.assign((element as HTMLElement).style, style);
    }
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || /^on/i.test(key)) continue;
      if (key === 'src' || key === 'srcset') {
        if (typeof value === 'string' && /^data:image\//i.test(value)) (element as HTMLImageElement).src = value;
        continue;
      }
      if (key === 'href') {
        const href = String(value);
        if (href.startsWith('#')) element.setAttribute('href', href);
        else if (href) element.setAttribute('title', href);
        continue;
      }
      if (key === 'srcdoc' || key === 'action' || key === 'formAction' || key === 'innerHTML' || key === 'outerHTML') continue;
      try { (element as unknown as Record<string, unknown>)[key] = value; } catch { /* 읽기 전용 속성은 건너뜀 */ }
    }
    children?.forEach((child) => element.appendChild(make(child)));
    // 그림 src는 docx-preview가 만든 뒤 비동기로 채운다(result.src = …). 그 뒤에도 data: 그림만 남도록 감시
    if (lower === 'img') guardImage(element as HTMLImageElement);
    return element;
  };
  return make;
}

function guardImage(image: HTMLImageElement) {
  // 틀 문서의 HTMLImageElement(없으면 — 시험용 문서처럼 창이 없는 문서 — 바깥 것)의 src 접근자를 감싼다
  const prototype = (image.ownerDocument.defaultView?.HTMLImageElement ?? HTMLImageElement).prototype;
  const descriptor = Object.getOwnPropertyDescriptor(prototype, 'src');
  if (!descriptor?.set || !descriptor.get) return;
  Object.defineProperty(image, 'src', {
    configurable: true,
    get() { return descriptor.get!.call(image); },
    set(value: unknown) { if (typeof value === 'string' && /^data:image\//i.test(value)) descriptor.set!.call(image, value); },
  });
}

export default function DocxFrame({ data, zoom, pageJump, page, onInfo, onPageChange, onFailure }: RendererProps) {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const latest = useRef({ onInfo, onPageChange, onFailure });
  latest.current = { onInfo, onPageChange, onFailure };
  const [ready, setReady] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [pageWidth, setPageWidth] = useState(0);
  const [containerWidth, setContainerWidth] = useState(0);

  useEffect(() => {
    if (!loaded) return;
    const frame = frameRef.current;
    const target = frame?.contentDocument;
    if (!frame || !target) { latest.current.onFailure('격리 틀을 만들지 못함'); return; }
    let cancelled = false;
    const started = performance.now();
    const timer = window.setTimeout(() => { if (!cancelled) latest.current.onFailure('그리기 제한 시간 초과'); }, FIRST_PAINT_TIMEOUT_MS);
    // docx-preview는 받은 두 자리를 비우고 채운다 → 머리(CSP·기본 CSS·배율)를 지키려고 본문 안 전용 자리 둘을 준다
    const bodySlot = target.getElementById('pg-docx-body');
    const styleSlot = target.getElementById('pg-docx-styles');
    if (!bodySlot || !styleSlot) { latest.current.onFailure('격리 틀을 만들지 못함'); return; }
    renderAsync(data.slice(0), bodySlot, styleSlot, {
      className: 'docx',
      inWrapper: true,
      breakPages: true,
      ignoreLastRenderedPageBreak: true,
      renderHeaders: true,
      renderFooters: true,
      renderFootnotes: true,
      renderEndnotes: true,
      renderComments: false,
      renderChanges: false,
      renderAltChunks: false,
      useBase64URL: true,
      experimental: false,
      h: frameElementFactory(target),
    } as Parameters<typeof renderAsync>[3]).then(() => {
      if (cancelled) return;
      window.clearTimeout(timer);
      const sections = target.querySelectorAll('section.docx');
      const first = sections[0] as HTMLElement | undefined;
      setPageWidth(first?.offsetWidth ?? 794);
      setReady(true);
      const ms = Math.round(performance.now() - started);
      scrollRef.current?.setAttribute('data-first-paint-ms', String(ms));
      latest.current.onInfo({ pages: Math.max(1, sections.length), firstPaintMs: ms });
    }, (error: unknown) => {
      if (cancelled) return;
      window.clearTimeout(timer);
      latest.current.onFailure(failureReason(error));
    });
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [loaded, data]);

  useLayoutEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const measure = () => setContainerWidth(element.clientWidth);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  // 배율: 틀 안 CSS zoom(틀 안은 인라인 스타일 허용). 틀 높이는 내용 높이에 맞춰 height 속성으로
  const effective = zoom === 'fit' ? (pageWidth > 0 && containerWidth > 0 ? Math.min(2, (containerWidth - 32) / pageWidth) : 1) : zoom;
  useEffect(() => {
    const target = frameRef.current?.contentDocument;
    if (!ready || !target) return;
    const rule = target.getElementById('pg-zoom');
    if (rule) rule.textContent = `.docx-wrapper{zoom:${effective.toFixed(3)}}`;
    const frame = frameRef.current!;
    const fit = () => { frame.height = String(Math.ceil(target.documentElement.scrollHeight)); };
    fit();
    const images = Array.from(target.images).filter((image) => !image.complete);
    images.forEach((image) => image.addEventListener('load', fit, { once: true }));
    latest.current.onInfo({ effectiveZoom: effective });
    return () => images.forEach((image) => image.removeEventListener('load', fit));
  }, [ready, effective]);

  useEffect(() => {
    const target = frameRef.current?.contentDocument;
    const root = scrollRef.current;
    const section = target?.querySelectorAll<HTMLElement>('section.docx')[page - 1];
    if (root && section && frameRef.current) root.scrollTop = frameRef.current.offsetTop + section.getBoundingClientRect().top - 8;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageJump]);

  const onScroll = () => {
    const target = frameRef.current?.contentDocument;
    const root = scrollRef.current;
    if (!target || !root || !frameRef.current) return;
    const line = root.scrollTop - frameRef.current.offsetTop + root.clientHeight / 3;
    let current = 1;
    target.querySelectorAll<HTMLElement>('section.docx').forEach((section, index) => {
      if (section.getBoundingClientRect().top + (target.defaultView?.scrollY ?? 0) <= line) current = index + 1;
    });
    latest.current.onPageChange(current);
  };

  return (
    <div className="pg-dv-scroll pg-dv-docx" ref={scrollRef} onScroll={onScroll} tabIndex={0} aria-label="DOCX 본문">
      {!ready && <p className="pg-dv-loading" role="status">DOCX를 그리는 중…</p>}
      <iframe ref={frameRef} className="pg-dv-docx-frame" title="DOCX 본문(격리된 보기)" sandbox="allow-same-origin" srcDoc={FRAME_DOC}
        referrerPolicy="no-referrer" onLoad={() => setLoaded(true)} data-ready={ready ? 'true' : 'false'} />
    </div>
  );
}
