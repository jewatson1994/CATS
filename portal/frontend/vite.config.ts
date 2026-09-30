import {defineConfig} from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig(({command}) => ({
  plugins: [react()],
  base: command === 'serve' ? '/' : '/static/frontend/',
  build: {outDir: '../app/static/frontend', emptyOutDir: true},
  server: {proxy: {'^/(?!src/|@|node_modules/)': {
    target: 'http://127.0.0.1:8000',
    bypass(request) {
      // Vite owns page HTML/HMR; FastAPI owns JSON, form posts and static assets.
      if (request.method === 'GET' && request.headers.accept?.includes('text/html') && !request.url?.startsWith('/static/')) return '/index.html';
    },
  }}},
  test: {environment: 'jsdom', setupFiles: ['./src/test-setup.ts']},
}));
