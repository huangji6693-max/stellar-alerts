import { defineConfig } from 'vitest/config';
import path from 'path';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Mirror the tsconfig `paths` mapping so tests resolve the shared workspace
      // package from its TypeScript source (no pre-built `packages/shared/dist/`).
      '@stellar-alerts/shared': path.resolve(__dirname, '../../packages/shared/src/index.ts'),
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'http://localhost' } },
    setupFiles: ['./vitest.setup.ts'],
    environmentMatchGlobs: [
      // Proxy/middleware tests run in Node — they use Buffer, crypto, and
      // import from next/server which is mocked in the test file itself.
      ['src/app/__tests__/proxy.test.ts', 'node'],
    ],
    include: ['src/**/*.test.{ts,tsx}'],
    testTimeout: 20000,
  },
});
