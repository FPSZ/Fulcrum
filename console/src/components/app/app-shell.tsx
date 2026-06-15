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
    <div className="h-screen overflow-hidden p-4">
      <div className="glass-panel flex h-full overflow-hidden rounded-[24px]">
        <Sidebar
          collapsed={navCollapsed}
          onToggle={() => setNavCollapsed((v) => !v)}
          active={active}
          onNavigate={onNavigate}
        />
        <div className="relative z-10 flex min-w-0 flex-1 flex-col">
          <Topbar title={title} onMenu={() => setNavCollapsed((v) => !v)} />
          <main className="flex min-h-0 flex-1 flex-col overflow-hidden">{children}</main>
        </div>
      </div>
    </div>
  )
}
