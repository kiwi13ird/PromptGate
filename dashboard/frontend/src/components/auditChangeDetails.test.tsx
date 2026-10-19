import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AuditChangeDetails } from './AuditChangeDetails';

describe('recorded audit changes', () => {
  it('shows both assignees, including a genuinely unassigned previous value', () => {
    render(<AuditChangeDetails changes={{ previousAssignee: '', newAssignee: 'reviewer-2' }} />);
    expect(screen.getByText('변경 전: 미지정')).toBeInTheDocument();
    expect(screen.getByText('변경 후: reviewer-2')).toBeInTheDocument();
    expect(screen.queryByText('정책 버전')).not.toBeInTheDocument();
  });
  it('does not treat a recorded zero or empty string as missing', () => {
    render(<AuditChangeDetails changes={{ previousVersion: 0, newVersion: 1, previousValue: '0', newValue: '' }} />);
    expect(screen.getByText('변경 전: v0')).toBeInTheDocument();
    expect(screen.getByText('변경 후: 빈 값')).toBeInTheDocument();
  });
  it('distinguishes an absent previous value from a recorded unassigned value', () => {
    render(<AuditChangeDetails changes={{ newAssignee: 'reviewer' }} />);
    expect(screen.getByText('변경 전: 당시 미기록')).toBeInTheDocument();
  });
  it('does not translate a name or raw configuration value that happens to equal an enum', () => {
    render(<AuditChangeDetails changes={{ newAssignee: 'NEW', previousValue: 'OFF', newValue: 'ON' }} />);
    expect(screen.getByText('변경 후: NEW')).toBeInTheDocument();
    expect(screen.getByText('변경 전: OFF')).toBeInTheDocument();
  });
  it('explains a login without changes rather than displaying irrelevant empty fields', () => {
    render(<AuditChangeDetails />);
    expect(screen.getByText(/변경 전·후 값이 기록되지/)).toBeInTheDocument();
    expect(screen.queryByText('최종 조치')).not.toBeInTheDocument();
  });
  it('links the reader to the event for a note without implying audit stores its contents', () => {
    render(<AuditChangeDetails changes={{ noteAdded: true }} />);
    expect(screen.getByText(/내용은 해당 이벤트에서/)).toBeInTheDocument();
  });
});
