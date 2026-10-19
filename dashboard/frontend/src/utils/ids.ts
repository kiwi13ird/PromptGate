export function generateResourceId(prefix: 'DOC' | 'AUD' | 'TL' | 'NOTE') {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return `${prefix}-${Array.from(bytes, (value) =>
    value.toString(16).padStart(2, '0'),
  )
    .join('')
    .toUpperCase()}`;
}
