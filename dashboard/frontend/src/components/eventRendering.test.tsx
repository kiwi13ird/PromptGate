import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  ActionBadge,
  DetectorBadge,
  IncidentStatusBadge,
} from './common';

describe('security event rendering', () => {
  it('renders action, detector and workflow status as text', () => {
    render(
      <>
        <ActionBadge action="BLOCK" />
        <DetectorBadge detector="MINHASH" />
        <DetectorBadge detector="WINDOW_HASH" />
        <IncidentStatusBadge status="INVESTIGATING" />
      </>,
    );
    expect(screen.getByText('차단')).toHaveClass('badge-block');
    expect(screen.getByText('유사 문서 검사')).toHaveAttribute('title', 'MINHASH');
    expect(screen.getByText('문서 구간 검사')).toHaveAttribute('title', 'WINDOW_HASH');
    expect(screen.getByText('조사 중')).toHaveClass('status-investigating');
    expect(screen.getByText('차단')).toHaveAttribute('title', '차단');
  });
});
