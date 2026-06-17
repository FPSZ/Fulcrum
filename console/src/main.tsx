import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import './index.css'
import { App } from './App'
import { registerFeatures } from './features/register'
import { queryClient } from './lib/query'

// 装配所有功能模块:导航 / 路由 / 备份资源一次性接上(新增页面只改 register.ts)
registerFeatures()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
)
