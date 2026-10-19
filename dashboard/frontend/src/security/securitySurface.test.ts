import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

function sourceFiles(root: string): string[] {
  return readdirSync(root).flatMap((name) => {
    const path = join(root, name);
    return statSync(path).isDirectory()
      ? sourceFiles(path)
      : /\.(ts|tsx)$/.test(name)
        ? [path]
        : [];
  });
}

describe('administrator security surface', () => {
  it('contains no external model tool bridge', () => {
    const current = relative(process.cwd(), import.meta.filename).replaceAll(
      '\\',
      '/',
    );
    const content = sourceFiles(join(process.cwd(), 'src'))
      .filter(
        (file) =>
          relative(process.cwd(), file).replaceAll('\\', '/') !== current,
      )
      .map((file) => readFileSync(file, 'utf8'))
      .join('\n')
      .toLowerCase();
    const forbidden = [
      'web' + 'mcp',
      'model' + 'context',
      'open_' + 'security_event',
      'change_' + 'detection_policy_status',
    ];
    for (const value of forbidden) expect(content).not.toContain(value);
  });
});
