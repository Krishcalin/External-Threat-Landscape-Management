import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // The console talks to the API on 8000 in development. Proxied rather than
    // hard-coded into the client so the built bundle carries no origin and can
    // be served from the API itself in a deployment.
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true } },
  },
})
