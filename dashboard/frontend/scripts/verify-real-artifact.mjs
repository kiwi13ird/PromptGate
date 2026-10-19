import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function validateRealManifest(manifest, readChunk) {
  assert.equal(manifest.schemaVersion, 1, 'Unsupported artifact manifest');
  assert.equal(manifest.mode, 'production', 'Production build is required');
  assert.equal(manifest.apiMode, 'real', 'HTTP API mode is required');
  assert.equal(manifest.hasMockModules, false, 'Mock modules are forbidden');
  assert.equal(manifest.realHttpAdaptersIncluded, true, 'Real HTTP adapters must be bundled');
  assert.deepEqual(manifest.runtimeAdapters, { gateway: 'src/api/httpAdapter.ts', auth: 'src/auth/realAuthAdapter.ts', ui: 'src/config/uiMode.real.ts' });
  if (manifest.runtimeSourceModules) validateRuntimeSources(manifest.runtimeSourceModules);
  assert.ok(Array.isArray(manifest.chunks) && manifest.chunks.length > 0, 'No verified JavaScript chunks');
  const seen = new Set();
  for (const chunk of manifest.chunks) {
    // .mjs = pdf.js 작업자(본문 보기, 2026-10-13). 실행되는 스크립트라 같은 해시 대조를 받는다
    assert.match(chunk.file, /^assets\/[A-Za-z0-9_.-]+\.m?js$/, 'Unsafe artifact path');
    assert.ok(!seen.has(chunk.file), 'Duplicate artifact path');
    seen.add(chunk.file);
    assert.match(chunk.sha256, /^[a-f0-9]{64}$/, 'Invalid artifact hash');
    const content=readChunk(chunk.file);
    assert.equal(createHash('sha256').update(content).digest('hex'), chunk.sha256, `Changed artifact: ${chunk.file}`);
    for (const marker of ['시연 준비 상태','시연 사례 바로가기','/api/demo/readiness','showcase:before-navigation','showcase:intro-reveal']) {
      assert.ok(!content.toString().includes(marker), `Presentation-only UI is forbidden: ${chunk.file}`);
    }
  }
  return seen;
}

export function validateRuntimeSources(modules) {
  assert.ok(Array.isArray(modules) && modules.length > 0, 'Actual runtime module inventory is required');
  for (const file of modules) {
    assert.match(file, /^(src|components|lib)\//, 'Unsafe runtime source path');
    assert.ok(!file.includes('..') && !/(^|\/)(mocks|__mocks__|fixtures|__fixtures__|samples)(\/|$)|\.(test|spec)\.|(^|\/)(mockAdapter|mockClient|mockAuthAdapter)\.|\/config\/uiMode\.mock/.test(file), `Fixture/test runtime module forbidden: ${file}`);
  }
  for (const expected of ['src/api/httpAdapter.ts','src/auth/realAuthAdapter.ts','src/config/uiMode.real.ts']) assert.ok(modules.includes(expected), `Missing real runtime source: ${expected}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(process.argv[2] ?? 'dist-real');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'artifact-manifest.json'), 'utf8'));
  validateRuntimeSources(manifest.runtimeSourceModules);
  const chunks = validateRealManifest(manifest, file => fs.readFileSync(path.join(root, file)));
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const entry = /<script[^>]+src="\/?(assets\/[^"]+\.js)"/.exec(html)?.[1];
  assert.ok(entry && chunks.has(entry), 'HTML entry must reference a verified chunk');
  for (const file of fs.readdirSync(path.join(root, 'assets'))) {
    assert.ok(!file.endsWith('.map'), 'Production sourcemaps must not be published');
    if (/\.m?js$/.test(file)) assert.ok(chunks.has('assets/' + file), 'Unverified JavaScript asset');
  }
  console.log(JSON.stringify({ productionArtifact: 'PASS', httpAdapters: 'PASS', mockModules: false, verifiedChunks: chunks.size }));
}
