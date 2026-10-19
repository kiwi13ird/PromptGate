import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolveBuildMode } from './src/config/buildMode.ts';

const configDirectory = path.dirname(fileURLToPath(import.meta.url));

// macOS Seatbelt blocks FSEvents, so Codex previews need polling for HMR.
const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === 'seatbelt';

export default defineConfig(({ mode }) => {
  const runtimeEnv = loadEnv(mode, configDirectory, '');
  const { gatewayAdapter, authAdapter, uiMode } =
    resolveBuildMode(mode, runtimeEnv);
  if (mode === 'production' && runtimeEnv.VITE_API_MODE !== 'real') throw new Error('Production Dashboard must use real HTTP APIs.');
  return {
    server: isCodexSeatbeltSandbox
      ? { watch: { useFsEvents: false, usePolling: true } }
      : undefined,
    plugins: [react(), {
      name: 'dashboard-artifact-integrity',
      writeBundle(options, bundle) {
        const chunks = Object.values(bundle).filter(item => item.type === 'chunk');
        // Document viewer (2026-10-13): the pdf.js worker is emitted as a ?url asset (.mjs). It runs as script, so it is hashed and verified like a chunk.
        const scriptAssets = Object.values(bundle).filter(item => item.type === 'asset' && /\.m?js$/.test(item.fileName));
        const modules = chunks.flatMap(chunk => Object.keys(chunk.modules)).map(id => id.replaceAll('\\', '/'));
        const runtimeSourceModules = [...new Set(modules.map(id => path.relative(configDirectory, id).replaceAll('\\', '/')).filter(id => /^(src|components|lib)\//.test(id)))].sort();
        const hasMockModules = runtimeSourceModules.some(id => /(^|\/)(mocks|__mocks__|fixtures|__fixtures__|samples)(\/|$)|\.(test|spec)\.|(^|\/)(mockAdapter|mockClient|mockAuthAdapter)\.|\/config\/uiMode\.mock/.test(id));
        if (runtimeEnv.VITE_API_MODE === 'real' && hasMockModules) throw new Error('Real artifact must not include mock modules.');
        const included = (file: string) => modules.some(id => id.endsWith('/' + file));
        const outputDirectory = path.resolve(configDirectory, options.dir ?? 'dist-real');
        // Hash final written bytes after Vite has rewritten lazy-import/preload references.
        writeFileSync(path.join(outputDirectory, 'artifact-manifest.json'), JSON.stringify({
          schemaVersion: 1,
          mode,
          apiMode: runtimeEnv.VITE_API_MODE,
          runtimeAdapters: { gateway: gatewayAdapter, auth: authAdapter, ui: uiMode },
          hasMockModules,
          runtimeSourceModules,
          realHttpAdaptersIncluded: included('src/api/httpAdapter.ts') && included('src/auth/realAuthAdapter.ts'),
          chunks: [...chunks, ...scriptAssets].map(chunk => ({ file: chunk.fileName, sha256: createHash('sha256').update(readFileSync(path.join(outputDirectory, chunk.fileName))).digest('hex') })),
        }, null, 2));
      },
    }],
    resolve: {
      alias: [
        {
          find: '@runtime/gateway-api',
          replacement: path.resolve(configDirectory, gatewayAdapter),
        },
        {
          find: '@runtime/auth-adapter',
          replacement: path.resolve(configDirectory, authAdapter),
        },
        {
          find: '@runtime/ui-mode',
          replacement: path.resolve(configDirectory, uiMode),
        },
        { find: '@', replacement: path.resolve(configDirectory, '.') },
      ],
    },
    build: {
      sourcemap: false,
      // Document viewer (2026-10-13): the pdf.js worker (?url asset) is .mjs in the package. The dashboard nginx mime.types has no mjs entry,
      // so it would be served as application/octet-stream and a module worker refuses it. Emit it as .js (served as JavaScript). Other assets keep the default name.
      rollupOptions: { output: { assetFileNames: (asset) => (/\.mjs$/.test(asset.names?.[0] ?? '') ? 'assets/[name]-[hash].js' : 'assets/[name]-[hash][extname]') } },
    },
  };
});
