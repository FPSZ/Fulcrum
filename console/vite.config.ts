import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

// 开发期把后端接口反代到同源(localhost:5173),让会话 Cookie(HttpOnly+SameSite=strict)
// 像单容器部署那样正常回传 —— 前端一律用相对路径调接口,开发/生产同源一致。
const API = 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    // 后端各业务前缀全部反代到 :8000;前端一律相对路径,开发/同源生产一致。
    // 缺任一前缀 → 该页 GET 命中 vite devserver(回 index.html)→ fetch 失败 → 永远回退演示 seed。
    proxy: {
      '/auth': { target: API, changeOrigin: true },
      '/admin': { target: API, changeOrigin: true },
      '/v1': { target: API, changeOrigin: true },
      '/tools': { target: API, changeOrigin: true },
      '/audit': { target: API, changeOrigin: true },
      '/overview': { target: API, changeOrigin: true },
      '/events': { target: API, changeOrigin: true },
      '/eval': { target: API, changeOrigin: true },
      '/policies': { target: API, changeOrigin: true },
      '/supply': { target: API, changeOrigin: true },
      '/healthz': { target: API, changeOrigin: true },
    },
  },
})
