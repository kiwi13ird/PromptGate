// PDF 쪽 그림(설계 6.3 PDF B안): pdf.js(pdfjs-dist 6.4.299)로 쪽마다 캔버스에 그린다. 이 파일은 본문 보기를 열 때만 불러온다(동적 import).
// - 레거시 판(legacy/build)을 쓴다: 최신 판은 Math.sumPrecise·Map.getOrInsertComputed 같은 아주 새 기능을 그대로 써서 조금 오래된 브라우저(모바일 Safari 등)에서 멈춘다.
// - 작업자(worker)는 같은 출처의 빌드 파일(?url)로만. 문서 안 스크립트는 돌리지 않는다(pdf.js 스크립팅을 쓰지 않음, 6.x는 eval을 쓰지 않는다).
// - 글꼴 대응표(CMap)·기호 글꼴·그림 해독기(wasm)도 같은 출처 파일로만 받는다(외부 CDN 없음). 링크·양식은 DOM으로 만들지 않는다(캔버스 그림만).
// - 보이는 쪽(+앞뒤 여유)만 그린다. 첫 쪽이 제한 시간 안에 안 그려지면 실패로 알린다.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';
import workerUrl from 'pdfjs-dist/legacy/build/pdf.worker.min.mjs?url';
import { FIRST_PAINT_TIMEOUT_MS, failureReason, type RendererProps } from './types';

type PdfDocument = Awaited<ReturnType<typeof pdfjs.getDocument>['promise']>;
type PdfRenderTask = ReturnType<Awaited<ReturnType<PdfDocument['getPage']>>['render']>;

const ASSET_URLS = import.meta.glob(
  ['/node_modules/pdfjs-dist/cmaps/*.bcmap', '/node_modules/pdfjs-dist/standard_fonts/FoxitSymbol.pfb', '/node_modules/pdfjs-dist/standard_fonts/FoxitDingbats.pfb', '/node_modules/pdfjs-dist/wasm/jbig2.wasm', '/node_modules/pdfjs-dist/wasm/openjpeg.wasm', '/node_modules/pdfjs-dist/wasm/qcms_bg.wasm'],
  { query: '?url', import: 'default', eager: true },
) as Record<string, string>;
const ASSET_BY_NAME = new Map(Object.entries(ASSET_URLS).map(([file, url]) => [file.slice(file.lastIndexOf('/') + 1), url]));

/** pdf.js가 작업자 대신 화면에 부탁하는 보조 파일(CMap·글꼴·wasm)을 같은 출처 빌드 파일에서만 준다. 목록에 없는 이름은 거절 */
class SameOriginBinaryDataFactory {
  constructor(_options: unknown) {}
  async fetch({ filename }: { kind: string; filename: string }) {
    const url = ASSET_BY_NAME.get(filename);
    if (!url) throw new Error(`pdf.js 보조 파일 없음: ${filename}`);
    const response = await fetch(url, { credentials: 'same-origin' });
    if (!response.ok) throw new Error(`pdf.js 보조 파일 응답 ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  }
}

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

const GUTTER = 16;
const MIN_SCALE = 0.25;
const MAX_SCALE = 4;

interface PageSize { width: number; height: number }

export default function PdfPages({ data, zoom, page, pageJump, onInfo, onPageChange, onFailure }: RendererProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const latest = useRef({ onInfo, onPageChange, onFailure });
  latest.current = { onInfo, onPageChange, onFailure };
  const [pdf, setPdf] = useState<PdfDocument | null>(null);
  const [baseSize, setBaseSize] = useState<PageSize | null>(null);
  const [sizes, setSizes] = useState<Record<number, PageSize>>({});
  const [containerWidth, setContainerWidth] = useState(0);
  const [visible, setVisible] = useState<ReadonlySet<number>>(new Set([1]));
  const painted = useRef(false);
  const started = useRef(0);

  // 문서 열기: 받은 바이트의 사본을 작업자로 넘긴다(pdf.js가 넘긴 버퍼를 떼어 가므로 원본은 뷰어가 그대로 가진다)
  useEffect(() => {
    let cancelled = false;
    painted.current = false;
    started.current = performance.now();
    const task = pdfjs.getDocument({
      data: new Uint8Array(data.slice(0)),
      useWorkerFetch: false,
      BinaryDataFactory: SameOriginBinaryDataFactory,
      enableXfa: false,
      stopAtErrors: false,
    } as Parameters<typeof pdfjs.getDocument>[0]);
    const timer = window.setTimeout(() => { if (!cancelled && !painted.current) latest.current.onFailure('그리기 제한 시간 초과'); }, FIRST_PAINT_TIMEOUT_MS);
    task.promise.then(async (loaded) => {
      const first = await loaded.getPage(1);
      const viewport = first.getViewport({ scale: 1 });
      if (cancelled) return;
      setBaseSize({ width: viewport.width, height: viewport.height });
      setPdf(loaded);
      latest.current.onInfo({ pages: loaded.numPages });
    }, (error: unknown) => { if (!cancelled) latest.current.onFailure(failureReason(error)); });
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      setPdf(null);
      void task.destroy();
    };
  }, [data]);

  useLayoutEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const measure = () => setContainerWidth(element.clientWidth);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const scale = useMemo(() => {
    if (!baseSize) return 1;
    const wanted = zoom === 'fit' ? (containerWidth - GUTTER * 2) / baseSize.width : zoom;
    return Math.min(MAX_SCALE, Math.max(MIN_SCALE, Number.isFinite(wanted) && wanted > 0 ? wanted : 1));
  }, [zoom, containerWidth, baseSize]);
  useEffect(() => { if (baseSize) latest.current.onInfo({ effectiveZoom: scale }); }, [scale, baseSize]);

  // 보이는 쪽 찾기(앞뒤 한 화면 여유)
  useEffect(() => {
    const root = scrollRef.current;
    if (!root || !pdf) return;
    const seen = new Set<number>();
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        const number = Number((entry.target as HTMLElement).dataset.page);
        if (entry.isIntersecting) seen.add(number); else seen.delete(number);
      }
      setVisible(new Set(seen));
    }, { root, rootMargin: '100% 0px' });
    root.querySelectorAll<HTMLElement>('[data-page]').forEach((element) => observer.observe(element));
    return () => observer.disconnect();
  }, [pdf]);

  // 도구 줄에서 쪽을 고르면 그 쪽으로
  useEffect(() => {
    const root = scrollRef.current;
    const target = root?.querySelector<HTMLElement>(`[data-page="${page}"]`);
    if (root && target) root.scrollTop = target.offsetTop - GUTTER;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageJump]);

  const onScroll = () => {
    const root = scrollRef.current;
    if (!root) return;
    const line = root.scrollTop + root.clientHeight / 3;
    let current = 1;
    for (const element of root.querySelectorAll<HTMLElement>('[data-page]')) {
      if (element.offsetTop <= line) current = Number(element.dataset.page); else break;
    }
    latest.current.onPageChange(current);
  };

  const count = pdf?.numPages ?? 0;
  const pages = Array.from({ length: count }, (_, index) => index + 1);
  return (
    <div className="pg-dv-scroll pg-dv-pdf" ref={scrollRef} onScroll={onScroll} tabIndex={0} aria-label="PDF 쪽">
      {!pdf && <p className="pg-dv-loading" role="status">PDF를 여는 중…</p>}
      {pdf && baseSize && pages.map((number) => {
        const size = sizes[number] ?? baseSize;
        return (
          <PdfPage key={number} pdf={pdf} number={number} scale={scale} size={size} active={visible.has(number)}
            onSize={(next) => setSizes((all) => (all[number]?.width === next.width && all[number]?.height === next.height ? all : { ...all, [number]: next }))}
            onPainted={() => {
              if (number !== 1 || painted.current) return;
              painted.current = true;
              const ms = Math.round(performance.now() - started.current);
              scrollRef.current?.setAttribute('data-first-paint-ms', String(ms));
              latest.current.onInfo({ firstPaintMs: ms });
            }}
            onError={(error) => { if (number === 1 && !painted.current) latest.current.onFailure(failureReason(error)); }} />
        );
      })}
    </div>
  );
}

function PdfPage({ pdf, number, scale, size, active, onSize, onPainted, onError }: {
  pdf: PdfDocument; number: number; scale: number; size: PageSize; active: boolean;
  onSize: (size: PageSize) => void; onPainted: () => void; onError: (error: unknown) => void;
}) {
  const holder = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [state, setState] = useState<'idle' | 'drawing' | 'done' | 'failed'>('idle');
  const drawnScale = useRef(0);
  const width = Math.round(size.width * scale);
  const height = Math.round(size.height * scale);

  // 자리 크기는 CSSOM으로만(문자열 style 속성 없음)
  useLayoutEffect(() => {
    const element = holder.current;
    if (!element) return;
    element.style.width = `${width}px`;
    element.style.height = `${height}px`;
  }, [width, height]);

  useEffect(() => {
    if (!active || drawnScale.current === scale) return;
    let cancelled = false;
    let task: PdfRenderTask | null = null;
    setState('drawing');
    (async () => {
      const pageProxy = await pdf.getPage(number);
      if (cancelled) return;
      const viewport = pageProxy.getViewport({ scale });
      onSize({ width: viewport.width / scale, height: viewport.height / scale });
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(viewport.width * ratio);
      canvas.height = Math.floor(viewport.height * ratio);
      canvas.style.width = `${Math.floor(viewport.width)}px`;
      canvas.style.height = `${Math.floor(viewport.height)}px`;
      const context = canvas.getContext('2d');
      if (!context) throw new Error('캔버스를 만들지 못함');
      task = pageProxy.render({ canvasContext: context, canvas, viewport, transform: ratio === 1 ? undefined : [ratio, 0, 0, ratio, 0, 0] } as Parameters<typeof pageProxy.render>[0]);
      await task.promise;
      if (cancelled) return;
      drawnScale.current = scale;
      setState('done');
      onPainted();
    })().catch((error: unknown) => {
      if (cancelled || (error as { name?: string })?.name === 'RenderingCancelledException') return;
      setState('failed');
      onError(error);
    });
    return () => { cancelled = true; task?.cancel(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, scale, pdf, number]);

  return (
    <div className="pg-dv-paper pg-dv-pdf-page" ref={holder} data-page={number} data-state={state} aria-label={`${number}쪽`} role="img">
      <canvas ref={canvasRef} />
      {state === 'failed' && <span className="pg-dv-page-error">이 쪽을 그리지 못함</span>}
    </div>
  );
}
