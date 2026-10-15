import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Bridge the legacy CRA env var so existing deploys keep working without
// changing any dashboard settings: prefer VITE_API_URL, fall back to the old
// REACT_APP_API_URL that Vercel already provides at build time.
const API_URL =
  process.env.VITE_API_URL || process.env.REACT_APP_API_URL || '';

export default defineConfig({
  plugins: [react()],

  // This project keeps JSX in plain .js files (CRA convention) — tell esbuild
  // to parse .js as JSX. The separator class [\\/] matches both POSIX and
  // Windows paths (Vite passes backslash paths on Windows).
  esbuild: { loader: 'jsx', include: /src[\\/].*\.jsx?$/, exclude: [] },
  optimizeDeps: { esbuildOptions: { loader: { '.js': 'jsx' } } },

  define: {
    'import.meta.env.VITE_API_URL': JSON.stringify(API_URL),
  },

  server: { port: 3000, open: true },

  // Keep the CRA output path so vercel.json (outputDirectory: frontend/build)
  // and any other tooling continue to work unchanged.
  build: { outDir: 'build', sourcemap: false },

  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/setupTests.js',
  },
});
