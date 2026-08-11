import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  root: '.',
  publicDir: 'public',
  build: {
    outDir: 'dist',
    target: 'esnext'
  },
  server: {
    port: 3000,
    open: true
  }
});
