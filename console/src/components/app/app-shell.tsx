import { useState, type ReactNode } from 'react'
import { Sidebar } from './sidebar'

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
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar
        collapsed={navCollapsed}
        onToggle={() => setNavCollapsed((v) => !v)}
        active={active}
        onNavigate={onNavigate}
      />
      <div className="flex min-w-0 flex-1 flex-col">{children}</div>
    </div>
  )
}
