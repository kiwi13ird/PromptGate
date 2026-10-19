import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { useOverviewPeriod } from './useOverviewPeriod';
function Test() { const [period, change] = useOverviewPeriod(); const location = useLocation(); return <><span>{period}</span><span>{location.search}</span><button onClick={() => change('30D')}>넓히기</button><button onClick={() => change('24H')}>기본</button></>; }
describe('shareable dashboard period', () => {
  it('reads a shared period and preserves other query parameters', () => {
    render(<MemoryRouter initialEntries={['/traffic?period=7D&x=keep']}><Test /></MemoryRouter>);
    expect(screen.getByText('7D')).toBeInTheDocument();
    fireEvent.click(screen.getByText('넓히기'));
    expect(screen.getByText('?period=30D&x=keep')).toBeInTheDocument();
    fireEvent.click(screen.getByText('기본'));
    expect(screen.getByText('?x=keep')).toBeInTheDocument();
  });
  it('rejects invalid periods', () => {
    render(<MemoryRouter initialEntries={['/overview?period=ALL']}><Test /></MemoryRouter>);
    expect(screen.getByText('24H')).toBeInTheDocument();
  });
});
