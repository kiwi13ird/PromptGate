import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ReviewLinkCopy } from './ReviewLinkCopy';
import { copyText } from '@/src/utils/copyText';
afterEach(() => vi.unstubAllGlobals());
describe('review links in HTTP environments', () => {
  it('copies only a canonical event URL with no session token or list filters', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    render(<ReviewLinkCopy eventId="evt/a"/>);
    fireEvent.click(screen.getByRole('button', { name: '검토 링크 복사' }));
    expect(await screen.findByRole('status')).toHaveTextContent('관리자 로그인');
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/events/evt%2Fa?view=compare`);
  });
  it('uses an HTTP-compatible fallback and removes the temporary field', async () => {
    vi.stubGlobal('navigator', {});
    const previous = document.execCommand;
    document.execCommand = vi.fn().mockReturnValue(true);
    const active = document.createElement('button'); document.body.appendChild(active); active.focus();
    try {
      expect(await copyText('public review link')).toBe(true);
      expect(document.execCommand).toHaveBeenCalledWith('copy');
      expect(document.querySelector('textarea[aria-hidden="true"]')).toBeNull();
      expect(document.activeElement).toBe(active);
    } finally { document.execCommand = previous; active.remove(); }
  });
  it('offers selectable manual copy instead of claiming success when copying is denied', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue(Error('denied')) } });
    const previous = document.execCommand; document.execCommand = vi.fn().mockReturnValue(false);
    try {
      render(<ReviewLinkCopy eventId="evt-a"/>);
      fireEvent.click(screen.getByRole('button', { name: '검토 링크 복사' }));
      const field = await screen.findByLabelText(/자동 복사가 제한/);
      expect(field).toHaveValue(`${window.location.origin}/events/evt-a?view=compare`);
      await waitFor(() => expect(field).toHaveFocus());
      expect(screen.queryByText('링크 복사됨')).toBeNull();
      expect(screen.queryByText('denied')).toBeNull();
    } finally { document.execCommand = previous; }
  });
});
