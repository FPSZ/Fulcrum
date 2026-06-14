import { motion } from 'motion/react'
import { ChevronUp, PanelLeft, Search, Shield } from 'lucide-react'
import { Avatar, IconButton, Kbd, Tooltip } from '@/components/ui'
import { cn } from '@/lib/utils'
import { ease } from '@/lib/motion'
import { FEATURE_GROUPS, getFeatures } from '@/lib/module'

export function Sidebar({
  collapsed,
  onToggle,
  active,
  onNavigate,
}: {
  collapsed: boolean
  onToggle: () => void
  active: string
  onNavigate: (id: string) => void
}) {
  const features = getFeatures()
  // 从功能模块注册表自动构建导航(按分组,组内按 order)
  const sections = FEATURE_GROUPS.map((group) => ({
    group,
    items: features.filter((f) => f.group === group),
  })).filter((s) => s.items.length > 0)

  return (
    <motion.aside
      animate={{ width: collapsed ? 56 : 244 }}
      transition={{ duration: 0.18, ease: ease.out }}
      className="flex shrink-0 flex-col overflow-hidden border-r border-line bg-canvas px-2 py-2.5"
    >
      {/* 工作区切换 + 收起 */}
      <div className={cn('flex items-center gap-2.5 px-2', collapsed && 'flex-col gap-2 px-0')}>
        <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md bg-accent shadow-xs">
          <Shield className="h-[15px] w-[15px] text-white" />
        </span>
        {!collapsed && (
          <span className="truncate text-[13px] font-semibold tracking-[-0.01em]">
            枢衡
            <span className="ml-1.5 text-[10px] font-medium uppercase tracking-[0.14em] text-ink-mute">
              Fulcrum
            </span>
          </span>
        )}
        <IconButton
          label={collapsed ? '展开侧栏' : '收起侧栏'}
          onClick={onToggle}
          className={cn(!collapsed && 'ml-auto')}
        >
          <PanelLeft className="h-4 w-4" />
        </IconButton>
      </div>

      {/* 命令搜索 */}
      <Tooltip content={collapsed ? '搜索 / 命令' : ''} side="right">
        <button
          type="button"
          className={cn(
            'focus-ring mx-0.5 mb-1 mt-2 flex items-center gap-2 rounded-sm border border-line bg-subtle px-2.5 py-1.5 text-[12px] text-ink-mute transition-colors hover:bg-surface-2',
            collapsed && 'justify-center px-0',
          )}
        >
          <Search className="h-[15px] w-[15px] shrink-0" />
          {!collapsed && (
            <>
              <span>搜索 / 命令</span>
              <Kbd className="ml-auto">⌘K</Kbd>
            </>
          )}
        </button>
      </Tooltip>

      {/* 导航(由功能模块注册表生成) */}
      <nav className="mt-1 min-h-0 flex-1 overflow-y-auto">
        {sections.map((sec) => (
          <div key={sec.group}>
            {!collapsed && (
              <div className="px-2.5 pb-1.5 pt-3 text-[10px] font-semibold uppercase tracking-[0.08em] text-ink-mute">
                {sec.group}
              </div>
            )}
            {collapsed && <div className="my-1.5 border-t border-line" />}
            {sec.items.map((f) => {
              const isActive = active === f.id
              const Icon = f.icon
              return (
                <Tooltip key={f.id} content={collapsed ? f.label : ''} side="right">
                  <button
                    type="button"
                    onClick={() => onNavigate(f.id)}
                    className={cn(
                      'focus-ring flex w-full items-center gap-2.5 rounded-sm px-2.5 py-1.5 text-[13px] font-normal text-ink-2 transition-colors',
                      'hover:bg-surface-2',
                      isActive && 'bg-accent/10 font-semibold text-accent-ink',
                      collapsed && 'justify-center px-0',
                    )}
                  >
                    <Icon
                      className={cn('h-4 w-4 shrink-0', isActive ? 'text-accent' : 'text-ink-3')}
                      strokeWidth={1.8}
                    />
                    {!collapsed && <span className="truncate">{f.label}</span>}
                    {!collapsed && typeof f.badge === 'number' && (
                      <span
                        className={cn(
                          'font-data ml-auto text-[11px]',
                          isActive
                            ? 'text-accent-ink'
                            : f.danger
                              ? 'font-semibold text-high'
                              : 'text-ink-mute',
                        )}
                      >
                        {f.badge}
                      </span>
                    )}
                  </button>
                </Tooltip>
              )
            })}
          </div>
        ))}
      </nav>

      {/* 用户 */}
      <div className="mt-1.5 border-t border-line pt-2">
        <button
          type="button"
          className={cn(
            'focus-ring flex w-full items-center gap-2.5 rounded-sm px-2 py-1.5 text-left transition-colors hover:bg-surface-2',
            collapsed && 'justify-center px-0',
          )}
        >
          <Avatar fallback="运" className="h-6 w-6" />
          {!collapsed && (
            <>
              <span className="min-w-0 leading-tight">
                <span className="block text-[12px] font-semibold">运营·林珩</span>
                <span className="block truncate text-[11px] text-ink-3">
                  雄安政务智能体 · 安全组
                </span>
              </span>
              <ChevronUp className="ml-auto h-[15px] w-[15px] shrink-0 text-ink-mute" />
            </>
          )}
        </button>
      </div>
    </motion.aside>
  )
}
