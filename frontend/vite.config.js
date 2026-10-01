import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// In development, every request to /api (REST and WebSocket) is forwarded to
// the FastAPI backend, so the frontend can use relative URLs and never hits CORS.
const BACKEND = process.env.CYPHERON_BACKEND || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: BACKEND, changeOrigin: true, ws: true },
    },
  },
})
