import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@echocrypt/crypto': fileURLToPath(new URL('../packages/crypto/src/index.ts', import.meta.url)),
    },
  },
  test: {
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Tests share one Mongo/Redis; run files one after another.
    fileParallelism: false,
  },
});
