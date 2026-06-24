import { motion } from 'motion/react'
import { LogOut, Sparkles } from 'lucide-react'
import { Avatar, IconButton, Tooltip } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useAuth } from '@/lib/auth'
import { useDevMode } from '@/lib/dev-mode'
import { ease } from '@/lib/motion'
import { FEATURE_GROUPS, getFeaturesFor } from '@/lib/module'

/**
 * 可收缩侧栏 —— 丝滑收起的关键:
 * 内容固定 244px 宽,外层 aside 只动 width 并裁切;图标恒定在左、绝不位移;
 * 标签/徽标/卡片只做透明度淡入淡出。全程零回流、零换行,所以不抖。
 */
export function Sidebar({
  collapsed,
  active,
  onNavigate,
}: {
  collapsed: boolean
  active: string
  onNavigate: (id: string) => void
}) {
  const { user, has, isLead, logout } = useAuth()
  const [devMode] = useDevMode()
  const features = getFeaturesFor(has, devMode, isLead)
  const displayName = user?.displayName || '未登录'
  const sections = FEATURE_GROUPS.map((group) => ({
    group,
    items: features.filter((f) => f.group === group),
  })).filter((s) => s.items.length > 0)

  /** 收起时淡出、不参与布局变化的统一类 */
  const fade = (...extra: (string | false)[]) =>
    cn('transition-opacity duration-200 ease-[var(--ease-out-quart)]', collapsed && 'opacity-0', ...extra)

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 244 }}
      transition={{ duration: 0.22, ease: ease.out }}
      className="relative z-10 shrink-0 overflow-hidden"
    >
      {/* 固定 244px 内容壳:宽度恒定 → 不回流;由 aside 裁切 */}
      <div className="flex h-full w-[244px] flex-col px-3 py-3.5">
        {/* 导航(品牌已上移到顶栏) */}
        <nav className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
          {sections.map((sec) => (
            <div key={sec.group}>
              {/* 分类名:收起时也保留(监测/管控… 2 字,窄条放得下) */}
              <div className="whitespace-nowrap px-2.5 pb-1.5 pt-3.5 text-[13px] font-semibold text-ink-mute">
                {sec.group}
              </div>
              {sec.items.map((f) => {
                const isActive = active === f.id
                const Icon = f.icon
                return (
                  <Tooltip key={f.id} content={collapsed ? f.label : ''} side="right">
                    <button
                      type="button"
                      onClick={() => onNavigate(f.id)}
                      className={cn(
                        'focus-ring group relative flex w-full items-center gap-2.5 rounded-[11px] px-2.5 py-2 text-[15px] font-medium text-ink-2 transition-colors',
                        !collapsed && 'hover:bg-white/55',
                        !collapsed && isActive && 'bg-surface font-semibold text-accent shadow-card',
                        collapsed && isActive && 'font-semibold text-accent',
                      )}
                    >
                      {/* 收起态:选中高亮 = 仅包住图标的圆角方块(不被固定壳撑成长条) */}
                      {collapsed && isActive && (
                        <span className="pointer-events-none absolute left-px top-1/2 h-9 w-9 -translate-y-1/2 rounded-[11px] bg-surface shadow-card" />
                      )}
                      <Icon
                        className={cn(
                          'relative z-[1] h-[18px] w-[18px] shrink-0',
                          isActive ? 'text-accent' : 'text-ink-3',
                        )}
                        strokeWidth={1.8}
                      />
                      <span className={fade('min-w-0 flex-1 truncate text-left')}>{f.label}</span>
                      {typeof f.badge === 'number' && (
                        <span
                          className={fade(
                            cn(
                              'tabnum grid h-[19px] min-w-[19px] shrink-0 place-items-center rounded-full px-1.5 text-[12.5px] font-bold text-white',
                              f.danger ? 'bg-crit' : 'bg-accent',
                            ),
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

        {/* AI 研判卡:收起时高度+透明度一起收掉(固定宽 → 内部不回流) */}
        <div
          className={cn(
            'overflow-hidden transition-all duration-200 ease-[var(--ease-out-quart)]',
            collapsed ? 'mb-0 max-h-0 opacity-0' : 'mb-2.5 max-h-[220px] opacity-100',
          )}
        >
          <div className="rounded-[14px] border border-line bg-white/65 p-3.5 shadow-card">
            <div className="flex items-center gap-1.5 whitespace-nowrap text-[14.5px] font-bold text-ink">
              <Sparkles className="h-[15px] w-[15px] text-accent" strokeWidth={1.9} />
              AI 安全研判
            </div>
            <button
              type="button"
              className="focus-ring mt-2.5 h-7 w-full whitespace-nowrap rounded-[8px] bg-accent text-[14px] font-semibold text-white transition-colors hover:bg-accent-hover"
            >
              打开研判台
            </button>
          </div>
        </div>

        {/* 用户 */}
        <div className="border-t border-line pt-2.5">
          <div className="flex w-full items-center gap-2.5 rounded-[10px] px-1.5 py-1.5 text-left transition-colors hover:bg-white/55">
            <Avatar fallback={displayName.slice(0, 1)} className="h-8 w-8 shrink-0 rounded-[10px]" />
            <span className={fade('min-w-0 flex-1 whitespace-nowrap leading-tight')}>
              <span className="block truncate text-[14.5px] font-semibold">{displayName}</span>
              <span className="block text-[13px] text-ink-3">{user?.username ?? '—'}</span>
            </span>
            <Tooltip content="退出登录" side="top">
              <IconButton
                label="退出登录"
                onClick={logout}
                className={fade('h-7 w-7 shrink-0', collapsed ? 'pointer-events-none' : '')}
              >
                <LogOut className="h-[15px] w-[15px]" />
              </IconButton>
            </Tooltip>
          </div>
        </div>
      </div>
    </motion.aside>
  )
}
