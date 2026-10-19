import fs from 'node:fs';
import path from 'node:path';
import { useState } from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import {
  BADGE_TONE_VALUES,
  PgBadge,
  PgConfirmDialog,
  PgDrawer,
  PgEmpty,
  PgError,
  PgFilterBar,
  PgPageHeader,
  PgPager,
  PgRefresh,
  PgSegment,
  PgSkeleton,
  PgStatusStrip,
  PgTabs,
  STRIP_WORD,
  badgeTone,
  clockText,
  confirmTitle,
  type BadgeTone,
  type StripLevel,
} from '@/src/components/pg';

// 재설계 2단계 공통 부품(설계 4장) 시험. 모양(색·크기)은 캡처로, 여기서는 구조·역할·규칙을 본다
afterEach(() => { vi.useRealTimers(); });

describe('PgPageHeader (4.1)', () => {
  it('renders an h1 title, a one-line description with the full text in title, and the right-side slots in fixed order', () => {
    render(<PgPageHeader title="보호 문서" description="아주 긴 설명 한 줄"
      refresh={<span>갱신</span>} secondary={<span>보조</span>} primary={<button type="button">문서 등록</button>} period={<span>기간</span>}
      tabs={<PgTabs label="보기" items={[{ href: '#a', label: '가', current: true }, { href: '#b', label: '나', current: false }]} />}
      strip={<PgStatusStrip level="ok" facts={['5개 중 5개 보호 중']} />} />);
    const header = screen.getByRole('heading', { level: 1, name: '보호 문서' }).closest('header') as HTMLElement;
    expect(within(header).getByText('아주 긴 설명 한 줄')).toHaveAttribute('title', '아주 긴 설명 한 줄');
    const slots = [...header.querySelectorAll('.pg-page-slot')].map((slot) => slot.textContent);
    expect(slots).toEqual(['기간', '문서 등록', '보조', '갱신']);   // 기간 → 주 행동 → 보조 → 갱신
    // 탭은 제목 줄 아래, 상태 띠는 머리 맨 아래
    const children = [...header.children].map((child) => child.className);
    expect(children).toEqual(['pg-page-header-row', 'pg-page-tabs', 'pg-strip pg-strip--ok']);
    expect(within(header).getByRole('link', { name: '가' })).toHaveAttribute('aria-current', 'page');
    expect(within(header).getByRole('link', { name: '나' })).not.toHaveAttribute('aria-current');
  });

  it('accepts the old PageHeader props: action → primary, status → refresh, eyebrow not drawn', () => {
    render(<PgPageHeader eyebrow="정책 관리" title="탐지 정책" action={<span>주</span>} status={<span>새로고침 자리</span>} />);
    const header = screen.getByRole('heading', { level: 1 }).closest('header') as HTMLElement;
    expect([...header.querySelectorAll('.pg-page-slot')].map((slot) => slot.className.replace('pg-page-slot ', ''))).toEqual(['pg-page-slot--primary', 'pg-page-slot--refresh']);
    expect(screen.queryByText('정책 관리')).toBeNull();
  });
});

describe('PgRefresh (4.1 · 4.9)', () => {
  it('shows the update time, a failed state with the last value, and an icon button named 새로고침', () => {
    const onRefresh = vi.fn();
    const at = Date.parse('2026-10-13T00:11:37Z');   // 서울 09:11:37
    const { rerender } = render(<PgRefresh updatedAt={at} fetching={false} onRefresh={onRefresh} />);
    expect(clockText(at)).toBe('09:11:37');
    expect(screen.getByText('09:11:37 갱신')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    expect(onRefresh).toHaveBeenCalledTimes(1);
    rerender(<PgRefresh updatedAt={at} fetching onRefresh={onRefresh} />);
    expect(screen.getByRole('button', { name: '새로고침' })).toBeDisabled();
    rerender(<PgRefresh updatedAt={at} fetching={false} failed onRefresh={onRefresh} />);
    expect(screen.getByRole('status')).toHaveTextContent('갱신 실패 · 09:11:37 값');
  });

  it('announces how many records were added under the same conditions', () => {
    const { rerender } = render(<PgRefresh updatedAt={1} fetching={false} onRefresh={() => {}} total={3} scope="24H" countLabel="관리자 활동" />);
    rerender(<PgRefresh updatedAt={2} fetching={false} onRefresh={() => {}} total={5} scope="24H" countLabel="관리자 활동" />);
    expect(screen.getByRole('button', { name: /관리자 활동 2건 증가/ })).toBeInTheDocument();
    rerender(<PgRefresh updatedAt={3} fetching={false} onRefresh={() => {}} total={6} scope="7D" countLabel="관리자 활동" />);
    expect(screen.queryByRole('button', { name: /건 증가/ })).toBeNull();   // 조건이 바뀌면 처음부터
  });
});

describe('PgStatusStrip (4.2)', () => {
  it.each<[StripLevel, string]>([
    ['ok', '정상'], ['warn', '주의'], ['bad', '이상'], ['unknown', '확인 불가'], ['progress', '진행 중'],
  ])('%s level shows the word %s with its class', (level, word) => {
    render(<PgStatusStrip level={level} facts={['Gateway 정상', null, false, '최신 기록 09:08']} end={<a href="/traffic">트래픽 및 성능 ›</a>} />);
    const strip = screen.getByRole('status', { name: '상태' });
    expect(strip).toHaveClass(`pg-strip--${level}`);
    expect(strip).toHaveAttribute('data-level', level);
    expect(within(strip).getByText(word)).toHaveClass('pg-strip-word');
    expect(within(strip).getByText('Gateway 정상 · 최신 기록 09:08')).toBeInTheDocument();   // 빈 사실은 건너뜀
    expect(within(strip).getByRole('link', { name: '트래픽 및 성능 ›' })).toBeInTheDocument();
  });

  it('has exactly five levels and accepts a custom word', () => {
    expect(Object.keys(STRIP_WORD)).toEqual(['ok', 'warn', 'bad', 'unknown', 'progress']);
    render(<PgStatusStrip level="bad" word="이상 1 · 주의 1" facts={['Relay 끊김 · RDS 느림']} />);
    expect(screen.getByText('이상 1 · 주의 1')).toBeInTheDocument();
  });
});

describe('badge value → tone (4.4)', () => {
  it('maps every value of the design table to its tone', () => {
    const table: Record<BadgeTone, string[]> = {
      block: ['차단', '끊김', '추출 실패', '인스턴스 이상', '차단 중'],
      mask: ['마스킹', '느림', '일반 표현', '탐지 반영 실패'],
      allow: ['허용', '정상', '보호 중', '완료', '실행 중', '활성', '연결 중'],
      info: ['승인 대기', '분석 중', '처리 중', '시작 중', '생성 중', '조사 중'],
      neutral: ['확인 불가', '중지됨', '비활성', '최근 활동', '해당 없음'],
    };
    for (const [tone, values] of Object.entries(table)) for (const value of values) expect([value, badgeTone(value)]).toEqual([value, tone]);
    // 표 값은 코드 표에 모두 들어 있다(추가 값은 표 뒤에)
    for (const [tone, values] of Object.entries(table)) expect(BADGE_TONE_VALUES[tone as BadgeTone].slice(0, values.length)).toEqual(values);
  });

  it('maps risk levels and action codes, ignores spaces, and falls back to neutral', () => {
    expect(['높음', '중간', '낮음'].map(badgeTone)).toEqual(['block', 'mask', 'neutral']);
    expect(['BLOCK', 'MASK', 'ALLOW'].map(badgeTone)).toEqual(['block', 'mask', 'allow']);
    expect(badgeTone(' 차단 ')).toBe('block');
    expect(badgeTone('처음 보는 값')).toBe('neutral');
    expect(badgeTone(undefined)).toBe('neutral');
    // 한 값이 두 계열에 들어 있지 않다
    const all = Object.values(BADGE_TONE_VALUES).flat();
    expect(new Set(all).size).toBe(all.length);
  });

  it('renders default, dot and tag variants', () => {
    render(<>
      <PgBadge value="승인 대기" />
      <PgBadge variant="dot" tone="allow">연결 중</PgBadge>
      <PgBadge variant="tag" value="ChatGPT" />
      <PgBadge>일반 표현</PgBadge>
    </>);
    expect(screen.getByText('승인 대기')).toHaveClass('pg-badge', 'pg-badge--info');
    expect(screen.getByText('연결 중')).toHaveClass('pg-badge--allow', 'pg-badge--dot');
    expect(screen.getByText('ChatGPT')).toHaveClass('pg-badge--tag');
    expect(screen.getByText('ChatGPT')).not.toHaveAttribute('data-tone');   // 태그는 계열 색 없음
    expect(screen.getByText('일반 표현')).toHaveClass('pg-badge--mask');
  });
});

describe('PgDrawer (4.8)', () => {
  function Harness({ onOpenChange }: { onOpenChange?: (open: boolean) => void }) {
    const [open, setOpen] = useState(false);
    return <>
      <button type="button" onClick={() => setOpen(true)}>변경 내용 보기</button>
      <PgDrawer open={open} onOpenChange={(next) => { setOpen(next); onOpenChange?.(next); }} title="변경 내용" description="정책 수정 · v3 → v4"
        actions={<Button variant="outline" onClick={() => setOpen(false)}>닫기 버튼</Button>}>
        <p>필드 전후</p>
        <a href="#x">세부 링크</a>
      </PgDrawer>
    </>;
  }

  it('opens as a labelled modal dialog with focus inside, and closes with Esc returning focus to the opener', async () => {
    const changed = vi.fn();
    render(<Harness onOpenChange={changed} />);
    const opener = screen.getByRole('button', { name: '변경 내용 보기' });
    opener.focus();
    fireEvent.click(opener);
    const drawer = await screen.findByRole('dialog', { name: '변경 내용' });
    expect(drawer).toHaveClass('pg-drawer');
    expect(within(drawer).getByText('정책 수정 · v3 → v4')).toBeInTheDocument();
    expect(within(drawer).getByText('필드 전후')).toBeInTheDocument();
    await waitFor(() => expect(drawer.contains(document.activeElement)).toBe(true));   // 포커스가 서랍 안으로
    fireEvent.keyDown(document.activeElement ?? drawer, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(changed).toHaveBeenLastCalledWith(false);
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it('closes with the close button and keeps Tab inside while open', async () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: '변경 내용 보기' }));
    const drawer = await screen.findByRole('dialog', { name: '변경 내용' });
    // 포커스 가두기: 모달이 열린 동안 바깥(연 버튼)은 접근성 트리·Tab 대상에서 빠진다
    expect(screen.queryByRole('button', { name: '변경 내용 보기' })).toBeNull();
    fireEvent.click(within(drawer).getByRole('button', { name: '닫기' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });
});

describe('table → card (4.6)', () => {
  const rows = (card: boolean) => render(
    <Table card={card} aria-label="감사 로그">
      <TableHeader><TableRow><TableHead>작업</TableHead><TableHead>결과</TableHead><TableHead>시각</TableHead><TableHead>관리</TableHead></TableRow></TableHeader>
      <TableBody>
        <TableRow data-tone="block"><TableCell data-card="title">정책 수정</TableCell><TableCell data-card="badge">실패</TableCell><TableCell data-card="info" data-label="시각">09:11</TableCell><TableCell data-card="actions"><Button>열기</Button></TableCell></TableRow>
      </TableBody>
    </Table>,
  );

  it('card tables keep table roles explicitly and carry the card roles on cells', () => {
    const { container } = rows(true);
    const table = screen.getByRole('table', { name: '감사 로그' });
    expect(table).toHaveAttribute('role', 'table');
    expect(table).toHaveClass('pg-table');
    expect(table.parentElement).toHaveClass('pg-table-wrap');
    expect(screen.getAllByRole('row').every((row) => row.getAttribute('role') === 'row')).toBe(true);
    expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['작업', '결과', '시각', '관리']);
    expect(screen.getAllByRole('cell').map((cell) => cell.getAttribute('data-card'))).toEqual(['title', 'badge', 'info', 'actions']);
    expect(container.querySelectorAll('[role="rowgroup"]')).toHaveLength(2);
  });

  it('tables without card keep exactly the old DOM (event screens)', () => {
    const { container } = rows(false);
    expect(container.querySelectorAll('[role]')).toHaveLength(0);
    expect(container.querySelector('[data-slot="table-container"]')).toHaveAttribute('class', 'relative w-full overflow-x-auto');
    expect(container.querySelector('table')).not.toHaveClass('pg-table');
  });

  it('the card rule is a container query at 720px covering every card role', () => {
    const css = fs.readFileSync(path.resolve(process.cwd(), 'src/styles/components.css'), 'utf8');
    expect(css).toMatch(/\.pg-table-wrap\s*\{\s*container:\s*pg-table\s*\/\s*inline-size/);
    const block = css.slice(css.indexOf('@container pg-table (max-width: 720px)'));
    expect(block.length).toBeGreaterThan(0);
    for (const role of ['title', 'badge', 'info', 'body', 'actions', 'hide']) expect(block).toContain(`td[data-card='${role}']`);
    expect(block).toMatch(/thead \{ position: absolute;/);   // 머리는 화면에서만 숨김(display:none 아님 → 역할 유지)
    expect(block).not.toMatch(/thead \{[^}]*display:\s*none/);
  });
});

describe('empty · error · loading · pager (4.5 · 4.9)', () => {
  it('empty state is one line with one next action', () => {
    render(<PgEmpty title="최근 24시간 이벤트 없음" action={<button type="button">기간 넓히기</button>} />);
    const empty = screen.getByRole('status');
    expect(empty).toHaveClass('pg-empty');
    expect(within(empty).getByRole('button', { name: '기간 넓히기' })).toBeInTheDocument();
  });

  it('page and inline errors offer one retry', () => {
    const retry = vi.fn();
    const { rerender } = render(<PgError message="연결 중 IP를 불러오지 못함" onRetry={retry} variant="inline" />);
    expect(screen.getByRole('alert')).toHaveClass('pg-error--inline');
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    rerender(<PgError message="시스템 상태를 불러오지 못했습니다." error={new Error('x')} onRetry={retry} />);
    expect(screen.getByRole('alert')).toHaveClass('pg-error--page');
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
    expect(retry).toHaveBeenCalledTimes(2);
  });

  it('skeleton announces loading at once but draws its shape only after 300ms', () => {
    vi.useFakeTimers();
    const { container } = render(<PgSkeleton shape="kpi-table" rows={5} />);
    expect(screen.getByRole('status', { name: '데이터를 불러오는 중' })).toHaveAttribute('aria-busy', 'true');
    expect(container.querySelectorAll('.pg-skeleton-block')).toHaveLength(0);
    act(() => { vi.advanceTimersByTime(299); });
    expect(container.querySelectorAll('.pg-skeleton-block')).toHaveLength(0);
    act(() => { vi.advanceTimersByTime(1); });
    expect(container.querySelectorAll('.pg-skeleton-kpi')).toHaveLength(4);
    expect(container.querySelectorAll('.pg-skeleton-row')).toHaveLength(5);
  });

  it('pager moves between pages and hides with a single page', () => {
    const onPage = vi.fn();
    const { rerender, container } = render(<PgPager page={1} totalPages={3} onPage={onPage} />);
    expect(screen.getByRole('button', { name: '이전 페이지' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: '다음 페이지' }));
    expect(onPage).toHaveBeenCalledWith(2);
    expect(screen.getByText('1 / 3쪽')).toBeInTheDocument();
    rerender(<PgPager page={1} totalPages={1} onPage={onPage} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe('PgFilterBar (4.7)', () => {
  it('shows search and two key filters, opens the rest, shows applied chips and resets', async () => {
    const removed = vi.fn();
    const reset = vi.fn();
    render(<PgFilterBar label="감사 로그 필터" search={<input aria-label="검색" />} filters={<><select aria-label="기간" /><select aria-label="작업 유형" /></>}
      more={<select aria-label="결과" />} moreCount={1} chips={[{ key: 'result', label: '결과: 실패', onRemove: removed }]} onReset={reset} />);
    const bar = screen.getByRole('search', { name: '감사 로그 필터' });
    const toggle = within(bar).getByRole('button', { name: /필터 더보기/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(within(bar).queryByLabelText('결과')).toBeNull();
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(within(bar).getByRole('group', { name: '필터 더보기' })).toContainElement(within(bar).getByLabelText('결과'));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await waitFor(() => expect(toggle).toHaveFocus());
    fireEvent.click(within(bar).getByRole('button', { name: '결과: 실패 지우기' }));
    fireEvent.click(within(bar).getByRole('button', { name: '초기화' }));
    expect([removed.mock.calls.length, reset.mock.calls.length]).toEqual([1, 1]);
  });
});

describe('PgSegment and PgConfirmDialog (4.11)', () => {
  it('segment is a radio group under its legend', () => {
    const change = vi.fn();
    render(<PgSegment legend="기간" name="d" value="1d" onChange={change} options={[{ value: '1h', label: '1시간' }, { value: '1d', label: '1일' }, { value: 'forever', label: '영구' }]} />);
    const group = screen.getByRole('group', { name: '기간' });
    const radios = within(group).getAllByRole('radio');
    expect(radios.map((radio) => (radio as HTMLInputElement).checked)).toEqual([false, true, false]);
    fireEvent.click(within(group).getByRole('radio', { name: '영구' }));
    expect(change).toHaveBeenCalledWith('forever');
  });

  it('confirm dialog: title "행동 · 대상", two lines, [취소][행동], danger = red filled', async () => {
    const confirm = vi.fn();
    render(<PgConfirmDialog open onOpenChange={() => {}} action="보호 중지" target="05_투자유치_자료.docx" danger
      change="이 문서와 같은 내용이 더 이상 차단되지 않습니다." reversible="보호 시작으로 다시 켤 수 있습니다." onConfirm={confirm} />);
    const dialog = await screen.findByRole('dialog', { name: '보호 중지 · 05_투자유치_자료.docx' });
    expect(confirmTitle('차단')).toBe('차단');
    expect(within(dialog).getByText('이 문서와 같은 내용이 더 이상 차단되지 않습니다.')).toBeInTheDocument();
    const footer = dialog.querySelector('[data-slot="dialog-footer"]') as HTMLElement;
    expect(within(footer).getAllByRole('button').map((button) => button.textContent)).toEqual(['취소', '보호 중지']);
    expect(within(dialog).getByRole('button', { name: '보호 중지' })).toHaveClass('pg-button-danger-solid');
    fireEvent.click(within(dialog).getByRole('button', { name: '보호 중지' }));
    expect(confirm).toHaveBeenCalledTimes(1);
  });
});
