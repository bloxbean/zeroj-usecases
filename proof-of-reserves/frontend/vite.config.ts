import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
export default defineConfig({
  plugins: [svelte()],
  build: { outDir: '../src/main/resources/static', emptyOutDir: true },
  server: { port: 5177, proxy: { '/api': 'http://localhost:8089' } },
});
