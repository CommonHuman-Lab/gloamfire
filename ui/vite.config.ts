import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../gloamfire/api/static',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks: (id: string) => {
          if (id.includes('node_modules/recharts') || id.includes('node_modules/d3'))
            return 'vendor-recharts'
          if (id.includes('node_modules/lucide-react'))
            return 'vendor-lucide'
          if (id.includes('node_modules/react'))
            return 'vendor-react'
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:7100',
    },
  },
})
