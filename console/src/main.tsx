import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { App } from './App'
import { registerBackupResources } from './features/register-backups'

// 注册所有可导入/导出的资源(events,后续逐步增加)
registerBackupResources()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
