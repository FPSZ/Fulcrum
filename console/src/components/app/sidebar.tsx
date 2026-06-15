import { motion } from 'motion/react'
import { LogOut, PanelLeft, Shield, Sparkles } from 'lucide-react'
import { Avatar, IconButton, Tooltip } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useAuth } from '@/lib/auth'
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
  const { logout } = useAuth()
  const features = getFeatures()
  const sections = FEATURE_GROUPS.map((group) => ({
    group,
    items: features.filter((f) => f.group === group),
  })).filter((s) => s.items.length > 0)

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 244 }}
      transition={{ duration: 0.2, ease: ease.out }}
      className="relative z-10 flex shrink-0 flex-col overflow-hidden border-r border-line bg-white/45 px-3 py-3.5"
    >
      {/* 品牌 */}
      <div className={cn('flex items-center gap-2.5 px-1', collapsed && 'flex-col gap-2 px-0')}>
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-[11px] bg-accent shadow-[0_6px_14px_-6px_rgba(59,110,246,0.6)]">
          <Shield className="h-[19px] w-[19px] text-white" strokeWidth={1.9} />
        </span>
        {!collapsed && (
          <span className="min-w-0 leading-tight">
            <span className="block truncate text-[16px] font-bold tracking-[-0.01em]">
              枢衡 <span className="font-medium text-ink-3">Fulcrum</span>
            </span>
            <span className="block text-[12.5px] text-ink-mute">智能体安全中台</span>
          </span>
        )}
        <IconButton
          label={collapsed ? '展开侧栏' : '收起侧栏'}
          onClick={onToggle}
          className={cn('h-7 w-7', !collapsed && 'ml-auto')}
        >
          <PanelLeft className="h-4 w-4" />
        </IconButton>
      </div>

      {/* 导航 */}
      <nav className="mt-2 min-h-0 flex-1 overflow-y-auto">
        {sections.map((sec) => (
          <div key={sec.group}>
            {!collapsed ? (
              <div className="px-2.5 pb-1.5 pt-3.5 text-[13px] font-semibold text-ink-mute">
                {sec.group}
              </div>
            ) : (
              <div className="mx-2 my-2 border-t border-line" />
            )}
            {sec.items.map((f) => {
              const isActive = active === f.id
              const Icon = f.icon
              return (
                <Tooltip key={f.id} content={collapsed ? f.label : ''} side="right">
                  <button
                    type="button"
                    onClick={() => onNavigate(f.id)}
                    className={cn(
                      'focus-ring group flex w-full items-center gap-2.5 rounded-[11px] px-2.5 py-2 text-[15px] font-medium text-ink-2 transition-colors',
                      'hover:bg-white/55',
                      isActive && 'bg-surface font-semibold text-accent shadow-card',
                      collapsed && 'justify-center px-0',
                    )}
                  >
                    <Icon
                      className={cn('h-[18px] w-[18px] shrink-0', isActive ? 'text-accent' : 'text-ink-3')}
                      strokeWidth={1.8}
                    />
                    {!collapsed && <span className="truncate">{f.label}</span>}
                    {!collapsed && typeof f.badge === 'number' && (
                      <span
                        className={cn(
                          'tabnum ml-auto grid h-[19px] min-w-[19px] place-items-center rounded-full px-1.5 text-[12.5px] font-bold text-white',
                          f.danger ? 'bg-crit' : 'bg-accent',
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

      {/* AI 研判卡 */}
      {!collapsed && (
        <div className="mb-2.5 rounded-[14px] border border-line bg-white/65 p-3.5 shadow-card">
          <div className="flex items-center gap-1.5 text-[14.5px] font-bold text-ink">
            <Sparkles className="h-[15px] w-[15px] text-accent" strokeWidth={1.9} />
            AI 安全研判
          </div>
          <p className="mt-1.5 text-[13px] leading-relaxed text-ink-3">
            实时分析多源输入、归因溯源与处置建议,辅助值班研判。
          </p>
          <button
            type="button"
            className="focus-ring mt-2.5 h-7 w-full rounded-[8px] bg-accent text-[14px] font-semibold text-white transition-colors hover:bg-accent-hover"
          >
            打开研判台
          </button>
        </div>
      )}

      {/* 用户 */}
      <div className="border-t border-line pt-2.5">
        <div
          className={cn(
            'flex w-full items-center gap-2.5 rounded-[10px] px-1.5 py-1.5 text-left transition-colors hover:bg-white/55',
            collapsed && 'justify-center px-0',
          )}
        >
          <Avatar fallback="运" className="h-8 w-8 rounded-[10px]" />
          {!collapsed && (
            <>
              <span className="min-w-0 leading-tight">
                <span className="block text-[14.5px] font-semibold">运营 · 林珩</span>
                <span className="block truncate text-[13px] text-ink-3">SecOps Operator</span>
              </span>
              <Tooltip content="退出登录" side="top">
                <IconButton label="退出登录" onClick={logout} className="ml-auto h-7 w-7">
                  <LogOut className="h-[15px] w-[15px]" />
                </IconButton>
              </Tooltip>
            </>
          )}
        </div>
      </div>
    </motion.aside>
  )
}
