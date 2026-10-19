import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { PgDelta, PgHBars, PgMiniBars, PgPeriod, PgRowMenu, PgSplitBar, share } from '@/src/components/pg';

// 재설계 3단계 공용 지표 부품(설계 5.1.1·5.9.1·8.2 3단계 '지표 부품 3~4개')과 행 ⋯ 메뉴·기간 세그먼트
describe('metric parts', () => {
  it('delta chip: arrow, amount and percent; colours only an increase of block/mask; previous 0 says so', () => {
    const { rerender, container } = render(<PgDelta current={31} previous={19} tone="block" />);
    expect(screen.getByText('▲ 12 · 63%')).toHaveClass('pg-delta', 'pg-delta--block');
    rerender(<PgDelta current={22} previous={25} tone="mask" />);
    expect(screen.getByText('▼ 3 · 12%')).not.toHaveClass('pg-delta--mask');
    rerender(<PgDelta current={5} previous={0} />);
    expect(screen.getByText('직전 0건')).toBeInTheDocument();
    rerender(<PgDelta current={4} previous={4} tone="block" />);
    expect(container.textContent).toBe('변화 없음');
  });
  it('stacked bars: one row per reason, longest row = 100%, parts named for screen readers, rows link to settings', () => {
    render(<MemoryRouter><PgHBars label="사유" rows={[
      { key: 'a', label: '개인정보', to: '/policies', parts: [{ tone: 'block', value: 1, name: '차단' }, { tone: 'mask', value: 3, name: '마스킹' }] },
      { key: 'b', label: '접속 차단', parts: [{ tone: 'block', value: 2, name: '차단' }, { tone: 'mask', value: 0, name: '마스킹' }] },
    ]} /></MemoryRouter>);
    const list = screen.getByRole('list', { name: '사유' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(2);
    expect(screen.getByRole('link', { name: /개인정보/ })).toHaveAttribute('href', '/policies');
    const first = screen.getByRole('img', { name: '개인정보 차단 1건, 마스킹 3건' });
    expect([...first.children].map((node) => (node as HTMLElement).style.width)).toEqual(['25%', '75%']);
    const second = screen.getByRole('img', { name: '접속 차단 차단 2건' });
    expect(second.children).toHaveLength(1);   // 0인 조각은 그리지 않음
    expect((second.children[0] as HTMLElement).style.width).toBe('50%');
  });
  it('split bar and small bars keep a minimum visible width/height and expose the numbers', () => {
    expect(share(1, 1000)).toBe(2);
    expect(share(0, 10)).toBe(0);
    render(<PgSplitBar label="보호 문서 상태" parts={[{ tone: 'allow', value: 4, name: '보호 중' }, { tone: 'info', value: 1, name: '분석 중' }, { tone: 'block', value: 0, name: '오류' }]} />);
    expect(screen.getByRole('img', { name: '보호 문서 상태: 보호 중 4, 분석 중 1, 오류 0' }).children).toHaveLength(2);
    render(<PgMiniBars label="처리 시간 분포" limitAfter="b" limitLabel="대기 3초" bars={[{ key: 'a', label: '~10ms', value: 4 }, { key: 'b', label: '~1초', value: 0 }, { key: 'c', label: '넘음', value: 2, tone: 'mask' }]} />);
    const plot = screen.getByRole('img', { name: '처리 시간 분포: ~10ms 4건, ~1초 0건, 넘음 2건' });
    const bars = plot.querySelectorAll('.pg-minibar');
    expect(bars[1]).toHaveClass('has-limit');
    expect((bars[0].querySelector('.pg-minibar-fill') as HTMLElement).style.height).toBe('100%');
    expect((bars[2].querySelector('.pg-minibar-fill') as HTMLElement).style.height).toBe('50%');
    expect(bars[2].querySelector('.pg-minibar-fill')).toHaveClass('pg-fill--mask');
  });
});

describe('row ⋯ menu and period segment', () => {
  it('opens a named menu with actions and links; danger items are marked', async () => {
    const stop = vi.fn();
    render(<PgRowMenu label="05_자료.docx" items={[{ label: '내려받기', href: '/file?download=1', download: true }, { label: '보호 중지', danger: true, onSelect: stop }]} />);
    expect(screen.queryByRole('menu')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '05_자료.docx 더보기' }));
    const menu = await screen.findByRole('menu', { name: '05_자료.docx 조치' });
    expect(within(menu).getByRole('menuitem', { name: '내려받기' })).toHaveAttribute('href', '/file?download=1');
    const danger = within(menu).getByRole('menuitem', { name: '보호 중지' });
    expect(danger).toHaveClass('pg-menu-item--danger');
    fireEvent.click(danger);
    expect(stop).toHaveBeenCalledTimes(1);
  });
  it('menu moves focus with arrows and closes with Esc back to its button', () => {
    render(<PgRowMenu label="정책 A" items={[{ label: '이력' }, { label: '비활성화', danger: true }]} />);
    const button = screen.getByRole('button', { name: '정책 A 더보기' });
    fireEvent.click(button);
    expect(button).toHaveAttribute('aria-expanded', 'true');
    const [first, second] = screen.getAllByRole('menuitem');
    expect(first).toHaveFocus();
    fireEvent.keyDown(first, { key: 'ArrowDown' });
    expect(second).toHaveFocus();
    fireEvent.keyDown(second, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
    expect(button).toHaveFocus();
  });
  it('period is a radio group named for screen readers', () => {
    const change = vi.fn();
    render(<PgPeriod label="보안 현황 조회 기간" value="24H" onChange={change} />);
    const group = screen.getByRole('group', { name: '보안 현황 조회 기간' });
    expect(within(group).getByRole('radio', { name: '24시간' })).toBeChecked();
    fireEvent.click(within(group).getByRole('radio', { name: '30일' }));
    expect(change).toHaveBeenCalledWith('30D');
  });
});
