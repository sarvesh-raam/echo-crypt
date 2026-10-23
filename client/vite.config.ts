import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const api = process.env.API_URL ?? 'http://localhost:4000';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@echocrypt/crypto': fileURLToPath(new URL('../packages/crypto/src/index.ts', import.meta.url)),
    },
  },
  server: {
    port: 5174,
    proxy: {
      '/api': api,
      '/health': api,
      '/socket.io': { target: api, ws: true },
    },
  },
  build: { target: 'es2022', sourcemap: true },
});
