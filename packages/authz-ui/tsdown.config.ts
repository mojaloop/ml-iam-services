import { defineConfig } from 'tsdown';

export default defineConfig([
  {
    entry: ['src/index.ts', 'src/client.ts'],
    format: ['esm', 'cjs'],
    outExtensions: ({ format }) =>
      format === 'cjs' ? { js: '.cjs', dts: '.d.cts' } : { js: '.js', dts: '.d.ts' },
    platform: 'neutral',
    target: 'es2020',
    dts: true,
    outDir: 'dist',
    clean: true,
    copy: [{ from: 'src/default.css', to: 'dist' }],
  },
  {
    entry: {
      elements: 'src/elements/index.tsx',
      'elements-define': 'src/elements/define.ts',
      'elements-names': 'src/elements/names.ts',
    },
    format: 'esm',
    outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
    platform: 'browser',
    target: 'es2022',
    dts: true,
    outDir: 'dist',
    clean: true,
    minify: true,
    define: { 'process.env.NODE_ENV': JSON.stringify('production') },
    deps: { alwaysBundle: [/./], onlyBundle: false },
    checks: { moduleLevelDirective: false },
  },
]);
