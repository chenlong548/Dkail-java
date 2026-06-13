import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      '/status': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/alerts': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/processes': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/network': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/resources': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
  resolve: {
    alias: {
      '@': '/src',
    },
  },
})
