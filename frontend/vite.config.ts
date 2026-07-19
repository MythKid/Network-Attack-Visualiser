import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// The dev server is pinned to 5173 with strictPort: a silently reassigned port
// would not match the backend's CORS / WebSocket Origin allowlist
// (http://localhost:5173, http://127.0.0.1:5173) and live data would be refused.
export default defineConfig({
  plugins: [react()],
  server: {
    host: 'localhost',
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: 'localhost',
    port: 5173,
    strictPort: true,
  },
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
    clearMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
  },
})
