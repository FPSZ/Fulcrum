import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

// 开发期把后端接口反代到同源(localhost:5173),让会话 Cookie(HttpOnly+SameSite=strict)
// 像单容器部署那样正常回传 —— 前端一律用相对路径调接口,开发/生产同源一致。
const API = 'http://127.0.0.1:8000'

// 第三方库分包:把"极少变 + 体量大"的 vendor 拆出独立 chunk,既消掉单 chunk >500kB 告警,
// 又让浏览器跨发版缓存命中(业务代码改了,vendor 哈希不变)。markdown 渲染生态(react-markdown
// 拉起的 unified/micromark/mdast/hast 一大棵树)只有助手页用,单独拆出不压首屏。
function vendorChunk(id: string): string | undefined {
  if (!id.includes('node_modules')) return undefined
  if (
    /[\\/](react-markdown|remark|rehype|micromark|mdast|hast|unist|unified|vfile|property-information|character-entities|decode-named-character-reference|comma-separated-tokens|space-separated-tokens|html-url-attributes|trim-lines|hastscript|web-namespaces|zwitch|longest-streak|devlop|trough|bail)/.test(
      id,
    )
  )
    return 'markdown'
  if (id.includes('@radix-ui')) return 'radix'
  if (id.includes('@tanstack')) return 'query'
  if (/[\\/](motion|framer-motion)/.test(id)) return 'motion'
  // react/react-dom 不单拆:与通用 vendor 互相引用会形成 Rollup 循环 chunk;
  // 一并归入 vendor(≈350kB,远低于 500kB 告警阈值)。
  return 'vendor'
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    rollupOptions: {
      output: { manualChunks: vendorChunk },
    },
  },
  server: {
    // 后端各业务前缀全部反代到 :8000;前端一律相对路径,开发/同源生产一致。
    // 缺任一前缀 → 该页 GET 命中 vite devserver(回 index.html)→ fetch 失败 → 永远回退演示 seed。
    proxy: {
      '/auth': { target: API, changeOrigin: true },
      '/admin': { target: API, changeOrigin: true },
      '/v1': { target: API, changeOrigin: true },
      '/gateway': { target: API, changeOrigin: true },
      '/tools': { target: API, changeOrigin: true },
      '/assistant': { target: API, changeOrigin: true },
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
