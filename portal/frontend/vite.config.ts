import {defineConfig} from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/static/frontend/',
  build: {outDir: '../app/static/frontend', emptyOutDir: true},
  server: {proxy: {'^/(?!src/|@|node_modules/|static/frontend/)': 'http://127.0.0.1:8000'}},
  test: {environment: 'jsdom', setupFiles: ['./src/test-setup.ts']},
});
