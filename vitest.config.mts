import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

/**
 * Tests run the way Node runs the service: ES modules loaded as they ship,
 * so a dependency that is ESM needs nothing said about it here.
 */
export default defineConfig({
  resolve: {
    alias: {
      // The same names the package declares in `imports`, resolved to the
      // sources so a test reads what a build compiles.
      '#src': fileURLToPath(new URL('./src', import.meta.url)),
      '#test': fileURLToPath(new URL('./test', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    globals: true,
    clearMocks: true,
    coverage: {
      reportsDirectory: 'coverage',
      exclude: ['dist/**', 'node_modules/**'],
    },
    projects: [
      { extends: true, test: { name: 'unit', include: ['test/unit/**/*.test.ts'] } },
      // Against the Ory services docker-compose.yaml starts.
      { extends: true, test: { name: 'integration', include: ['test/integration/**/*.test.ts'] } },
    ],
  },
});
