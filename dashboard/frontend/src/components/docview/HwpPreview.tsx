// HWP·HWPX 대체 보기(설계 6.3 HWP C안): 원본 파일 안의 첫 쪽 미리보기 그림 + 탐지 기준 텍스트.
//  HWP(5.0, 복합 문서) → PrvImage 스트림 / HWPX(zip) → Preview/PrvImage.png
//  그림은 머리(PNG·GIF·BMP·JPEG)를 확인한 것만, 64×64 이하(가림 도구가 다시 쓴 자리 표시)는 그림 없음으로 본다.
//  그림은 blob 주소 없이 createImageBitmap → 캔버스로 그린다(img-src 정책과 무관, 닫으면 메모리만 놓음).
// 원본 모양(쪽 배치·글꼴) 그리기는 하지 않는다(설계 9장). 텍스트는 뷰어가 아래에 붙인다(textSlot).
import { useEffect, useRef, useState, type ReactNode } from 'react';
import JSZip from 'jszip';
import { isCfb, readCfbStream } from '@/src/utils/docview/cfb';
import { isPlaceholderImage, sniffImage, type PreviewImageInfo } from '@/src/utils/docview/image';
import { failureReason, type RendererProps } from './types';

type PreviewState =
  | { kind: 'loading' }
  | { kind: 'image'; info: PreviewImageInfo; bitmap: ImageBitmap }
  | { kind: 'none'; reason: string };

export async function extractPreview(data: ArrayBuffer, format: 'hwp' | 'hwpx'): Promise<{ bytes: Uint8Array | null; reason?: string }> {
  const bytes = new Uint8Array(data);
  if (format === 'hwp') {
    if (!isCfb(bytes)) return { bytes: null, reason: 'HWP 파일 구조가 아님' };
    const stream = readCfbStream(bytes, 'PrvImage');
    return stream && stream.length ? { bytes: stream } : { bytes: null, reason: '미리보기 그림이 없는 파일' };
  }
  const zip = await JSZip.loadAsync(data.slice(0));
  const entry = zip.file('Preview/PrvImage.png') ?? zip.file(/^Preview\/PrvImage\.[a-z]+$/i)[0] ?? null;
  if (!entry) return { bytes: null, reason: '미리보기 그림이 없는 파일' };
  return { bytes: await entry.async('uint8array') };
}

export default function HwpPreview({ data, format, onInfo, onFailure, textSlot }: RendererProps & { format: 'hwp' | 'hwpx'; textSlot: ReactNode }) {
  const latest = useRef({ onInfo, onFailure });
  latest.current = { onInfo, onFailure };
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [state, setState] = useState<PreviewState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    let bitmap: ImageBitmap | null = null;
    const started = performance.now();
    setState({ kind: 'loading' });
    (async () => {
      const { bytes, reason } = await extractPreview(data, format);
      if (!bytes) return { kind: 'none', reason: reason ?? '미리보기 그림 없음' } as const;
      const info = sniffImage(bytes);
      if (!info) return { kind: 'none', reason: '미리보기 그림 형식을 확인하지 못함' } as const;
      if (isPlaceholderImage(info)) return { kind: 'none', reason: `자리 표시 그림(${info.width}×${info.height})만 있음` } as const;
      bitmap = await createImageBitmap(new Blob([bytes.slice()], { type: info.type }));
      return { kind: 'image', info, bitmap } as const;
    })().then((next) => {
      if (cancelled) { bitmap?.close(); return; }
      setState(next);
      latest.current.onInfo({ pages: 1, firstPaintMs: Math.round(performance.now() - started), note: next.kind === 'image' ? '첫 쪽 미리보기 그림 + 텍스트' : '텍스트만' });
    }, (error: unknown) => {
      // 그림을 못 꺼내도 텍스트는 보인다 — 실패로 텍스트 보기로 바꾸지 않고 이 자리에만 알린다
      if (!cancelled) setState({ kind: 'none', reason: failureReason(error) });
    });
    return () => { cancelled = true; bitmap?.close(); };
  }, [data, format]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (state.kind !== 'image' || !canvas) return;
    canvas.width = state.bitmap.width;
    canvas.height = state.bitmap.height;
    canvas.getContext('2d')?.drawImage(state.bitmap, 0, 0);
    canvas.parentElement?.setAttribute('data-first-paint-ms', '1');
  }, [state]);

  return (
    <div className="pg-dv-scroll pg-dv-hwp" tabIndex={0} aria-label={`${format.toUpperCase()} 미리보기와 텍스트`}>
      <p className="pg-dv-hwp-note">{format.toUpperCase()}는 원본 모양을 그리지 않습니다 · 첫 쪽 미리보기 그림과 탐지 기준 텍스트를 보여 줍니다 · 글자만 넓게 보려면 텍스트 보기</p>
      <div className="pg-dv-hwp-body">
        <figure className="pg-dv-hwp-preview" data-state={state.kind}>
          {state.kind === 'image' && <canvas ref={canvasRef} role="img" aria-label={`첫 쪽 미리보기 그림 ${state.info.width}×${state.info.height}`} />}
          {state.kind === 'loading' && <span className="pg-dv-loading" role="status">미리보기 그림을 찾는 중…</span>}
          {state.kind === 'none' && <span className="pg-dv-hwp-noimage">첫 쪽 그림 없음 · {state.reason}</span>}
          {state.kind === 'image' && <figcaption>첫 쪽 미리보기(파일에 저장된 그림)</figcaption>}
        </figure>
        <div className="pg-dv-hwp-text">{textSlot}</div>
      </div>
    </div>
  );
}
