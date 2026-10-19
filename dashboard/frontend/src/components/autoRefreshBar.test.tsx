import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AutoRefreshBar, liveQueryOptions } from './AutoRefreshBar';

describe('visible-page refreshing', () => {
  it('offers compact header presentation without changing refresh or growth behavior', () => {
    const refresh = vi.fn(), onNew = vi.fn();
    const props = { compact: true, updatedAt: Date.now(), fetching: false, onRefresh: refresh, onNew, scope: '30D' };
    const view = render(<AutoRefreshBar {...props} total={10} />);
    expect(view.container.querySelector('.console-refresh')).not.toBeNull();
    expect(screen.queryByText(/10초마다 자동 갱신/)).toBeNull();
    view.rerender(<AutoRefreshBar {...props} total={12} />);
    fireEvent.click(screen.getByRole('button', { name: /최신 기록 보기/ }));
    expect(onNew).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    expect(refresh).toHaveBeenCalledOnce();
  });
  it('polls every ten seconds without enabling background polling', () => {
    expect(liveQueryOptions).toMatchObject({ refetchInterval: 10000, refetchIntervalInBackground: false, refetchOnWindowFocus: true });
  });
  it('announces count growth but not the initial load or filter changes', () => {
    const props = { updatedAt: 0, fetching: false, onRefresh: vi.fn(), scope: '24H' };
    const view = render(<AutoRefreshBar {...props} total={10} />);
    expect(screen.queryByText(/이벤트 .*건 증가/)).not.toBeInTheDocument();
    view.rerender(<AutoRefreshBar {...props} total={12} />);
    expect(screen.getByText(/이벤트 2건 증가/)).toBeInTheDocument();
    view.rerender(<AutoRefreshBar {...props} total={30} scope="7D" />);
    expect(screen.queryByText(/이벤트 .*건 증가/)).not.toBeInTheDocument();
  });
  it('allows manual refresh and communicates a failed update', () => {
    const refresh = vi.fn();
    render(<AutoRefreshBar updatedAt={Date.now()} fetching={false} failed onRefresh={refresh} />);
    expect(screen.getByText(/갱신 실패/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    expect(refresh).toHaveBeenCalledOnce();
  });
  it('does not claim a last successful result exists before any successful request', () => {
    render(<AutoRefreshBar updatedAt={0} fetching={false} failed onRefresh={vi.fn()} />);
    expect(screen.getByText(/조회 실패 · 서버 연결을/)).toBeInTheDocument();
    expect(screen.queryByText(/마지막 성공 조회 결과/)).not.toBeInTheDocument();
  });
  it('opens the newest-record callback, keeps it absent on initial load and suppresses it on failed reads',()=>{
    const onNew=vi.fn();
    const props={updatedAt:Date.now(),fetching:false,onRefresh:vi.fn(),scope:'24H',onNew};
    const view=render(<AutoRefreshBar {...props} total={10}/>);
    expect(screen.queryByText(/최신 기록 보기/)).not.toBeInTheDocument();
    view.rerender(<AutoRefreshBar {...props} total={12}/>);
    fireEvent.click(screen.getByRole('button',{name:/최신 기록 보기/}));
    expect(onNew).toHaveBeenCalledOnce();
    view.rerender(<AutoRefreshBar {...props} total={13} failed/>);
    expect(screen.queryByRole('button',{name:/최신 기록 보기/})).not.toBeInTheDocument();
  });
});
