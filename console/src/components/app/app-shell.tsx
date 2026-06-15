import { useState, type ReactNode } from 'react'
import { ChevronLeft } from 'lucide-react'
import { cn } from '@/lib/utils'
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
        <Sidebar collapsed={navCollapsed} active={active} onNavigate={onNavigate} />
        <div className="relative z-10 flex min-w-0 flex-1 flex-col">
          {/* T 字路口:侧栏竖线 × 顶栏横线交叉点上的悬浮收缩钮(收/展两态都可点)。
              箭头方向编码状态(展开→朝右、收起→朝左);hover/focus 再叠一圈弹簧旋转做反馈。 */}
          <button
            type="button"
            onClick={() => setNavCollapsed((v) => !v)}
            aria-label={navCollapsed ? '展开侧栏' : '收起侧栏'}
            className={cn(
              'focus-ring group absolute left-0 top-14 z-40 grid h-7 w-7 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-full',
              'border border-line-2 bg-surface/95 text-ink-3 backdrop-blur-sm',
              'shadow-[0_2px_8px_-2px_rgba(26,36,70,0.25),0_0_0_1px_rgba(255,255,255,0.55)]',
              'transition-[transform,color,border-color,box-shadow] duration-200',
              'hover:scale-105 hover:border-accent/45 hover:text-accent hover:shadow-[0_5px_16px_-3px_rgba(59,110,246,0.45)]',
              'active:scale-95',
            )}
          >
            <span className="transition-transform duration-300 ease-[var(--ease-spring)] group-hover:rotate-180 group-focus-visible:rotate-180">
              <ChevronLeft
                className={cn('h-[15px] w-[15px] transition-transform duration-300', !navCollapsed && 'rotate-180')}
              />
            </span>
          </button>
          <Topbar title={title} />
          <main className="flex min-h-0 flex-1 flex-col overflow-hidden">{children}</main>
        </div>
      </div>
    </div>
  )
}
