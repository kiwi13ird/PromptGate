import { defineConfig, loadEnv } from 'vite';
import productionConfig from './vite.config.ts';

// Packaging-only development convenience. The production configuration is unchanged.
export default defineConfig((context) => {
  const base = typeof productionConfig === 'function' ? productionConfig(context) : productionConfig;
  const environment = loadEnv(context.mode, process.cwd(), '');
  const target = environment.VITE_DEV_PROXY_TARGET;
  return {
    ...base,
    server: {
      ...base.server,
      ...(target ? { proxy: { '/api': { target, changeOrigin: true } } } : {}),
    },
  };
});
