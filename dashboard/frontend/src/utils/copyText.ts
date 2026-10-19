// HTTP demo environments may not expose navigator.clipboard. Keep a visible
// manual-copy fallback in the caller if both browser mechanisms refuse access.
export async function copyText(value: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(value); return true; } catch { /* Try the HTTP-compatible path. */ }
  }
  if (typeof document.execCommand !== 'function') return false;
  const active = document.activeElement;
  const selection = window.getSelection();
  const ranges = selection ? Array.from({ length: selection.rangeCount }, (_, index) => selection.getRangeAt(index).cloneRange()) : [];
  const field = document.createElement('textarea');
  field.value = value;
  field.setAttribute('readonly', '');
  field.setAttribute('aria-hidden', 'true');
  field.style.position = 'fixed';
  field.style.left = '-9999px';
  document.body.appendChild(field);
  try { field.select(); return document.execCommand('copy'); } catch { return false; }
  finally {
    field.remove();
    if (active instanceof HTMLElement) active.focus({ preventScroll: true });
    if (selection) { selection.removeAllRanges(); ranges.forEach(range => selection.addRange(range)); }
  }
}
