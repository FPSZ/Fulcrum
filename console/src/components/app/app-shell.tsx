import { useState, type ReactNode } from 'react'
import { getFeature } from '@/lib/module'
import { Sidebar } from './sidebar'
import { Topbar } from './topbar'

export function AppShell({
  active,
  onNavigate,
  children,
}: {
  active: string
  onNavigate: (id: string) => void
  children: ReactNode
}) {
  const [navCollapsed, setNavCollapsed] = useState(false)
  const title = getFeature(active)?.label ?? '控制台'

  return (
    <div className="h-screen overflow-hidden">
      {/* 外层"框"= 横贯顶部的顶栏 + 左侧栏连成一体的磨砂面(比内容透一些) */}
      <div
        className="glass-panel flex h-full flex-col overflow-hidden"
        style={{ background: 'rgba(255, 255, 255, 0.86)' }}
      >
        <Topbar
          title={title}
          collapsed={navCollapsed}
          onToggle={() => setNavCollapsed((v) => !v)}
        />
        <div className="flex min-h-0 flex-1 overflow-hidden">
          <Sidebar collapsed={navCollapsed} active={active} onNavigate={onNavigate} />
          {/* 内容面:近不透明白面(留一点点透气);只在与外框交界的左/上做小圆角+发丝边,右、下出血到边缘 */}
          <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
            <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-tl-[28px] border-l border-t border-line bg-white/85 backdrop-blur-sm">
              {children}
            </div>
          </main>
        </div>
      </div>
    </div>
  )
}
