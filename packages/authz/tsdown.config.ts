import { fileURLToPath } from 'node:url';
import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', 'src/gateway.ts', 'src/document.ts'],
  format: ['esm', 'cjs'],
  outExtensions: ({ format }) =>
    format === 'cjs' ? { js: '.cjs', dts: '.d.cts' } : { js: '.js', dts: '.d.ts' },
  alias: { '~': fileURLToPath(new URL('src', import.meta.url)) },
  dts: true,
  outDir: 'dist',
  clean: true,
});
