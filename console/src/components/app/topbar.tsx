import { useEffect, useState } from 'react'
import { Bell, HelpCircle, Images, Menu, PanelLeft, Radio, Search, Shield } from 'lucide-react'
import { IconButton, Kbd } from '@/components/ui'
import { BACKGROUNDS, useBackground } from '@/lib/background'
import { useTranslation } from '@/lib/i18n'

const pad = (n: number) => String(n).padStart(2, '0')

/** 全局实时时钟:每秒自走,任意页面都能看到当前监测时间 */
function LiveClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  const time = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`
  return (
    <span className="tabnum flex h-9 items-center gap-2 rounded-[11px] border border-line bg-surface/70 px-3 text-[14px] font-semibold text-ink">
      <Radio className="h-[15px] w-[15px] text-ok" strokeWidth={2.2} />
      {time}
    </span>
  )
}

/**
 * 全局顶栏(横贯整条顶部):左起 收缩钮 + 品牌 + 当前区域标题;
 * 右侧 实时时钟 + 全局检索 + 切换背景(多于一张时) / 帮助 / 告警。
 * 头像不放这里 —— 左下角侧栏已有用户区。
 */
export function Topbar({
  title,
  collapsed,
  onToggle,
  onMenu,
}: {
  title: string
  collapsed: boolean
  onToggle: () => void
  onMenu: () => void
}) {
  const { current, cycle } = useBackground()
  const { t } = useTranslation()
  return (
    <header className="flex h-14 shrink-0 items-center gap-2.5 pl-2.5 pr-3 md:h-20 md:gap-3 md:pl-3 md:pr-4">
      {/* 移动端:汉堡打开抽屉 */}
      <IconButton
        label={t('app.topbar.menu')}
        variant="ghost"
        className="h-9 w-9 rounded-[10px] md:hidden"
        onClick={onMenu}
      >
        <Menu className="h-[20px] w-[20px]" strokeWidth={1.9} />
      </IconButton>
      {/* 桌面:收起/展开侧栏 */}
      <IconButton
        label={collapsed ? t('app.topbar.expand_sidebar') : t('app.topbar.collapse_sidebar')}
        variant="ghost"
        className="hidden h-9 w-9 rounded-[10px] md:inline-flex"
        onClick={onToggle}
      >
        <PanelLeft className="h-[18px] w-[18px]" strokeWidth={1.9} />
      </IconButton>

      {/* 品牌:移动端隐藏(抽屉里已有),桌面显示 */}
      <div className="hidden items-center gap-2.5 md:flex">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-[11px] bg-accent shadow-[0_6px_14px_-6px_rgba(59,110,246,0.6)]">
          <Shield className="h-[19px] w-[19px] text-white" strokeWidth={1.9} />
        </span>
        <span className="whitespace-nowrap text-[16px] font-bold leading-none tracking-[-0.01em]">
          枢衡 <span className="font-medium text-ink-3">Fulcrum</span>
        </span>
      </div>

      <span className="mx-1 hidden h-5 w-px shrink-0 bg-line md:block" />
      <h1 className="truncate text-[16px] font-semibold tracking-[-0.01em] text-ink">{title}</h1>

      <div className="ml-auto flex items-center gap-2">
        <span className="hidden md:block">
          <LiveClock />
        </span>
        <button
          type="button"
          className="focus-ring hidden h-9 w-[260px] max-w-[34vw] items-center gap-2 rounded-[11px] border border-line bg-surface/70 px-3 text-[14.5px] text-ink-mute transition-colors hover:border-line-2 lg:flex"
        >
          <Search className="h-[15px] w-[15px] shrink-0" strokeWidth={1.9} />
          <span className="truncate">{t('app.topbar.search_placeholder')}</span>
          <Kbd className="ml-auto">⌘K</Kbd>
        </button>
        {/* 移动端:检索收成图标 */}
        <IconButton label={t('app.topbar.search')} variant="secondary" className="h-9 w-9 rounded-full lg:hidden">
          <Search className="h-[17px] w-[17px]" strokeWidth={1.9} />
        </IconButton>
        {BACKGROUNDS.length > 1 && (
          <IconButton
            label={t('app.topbar.switch_bg', { name: current.name })}
            variant="secondary"
            className="hidden h-9 w-9 rounded-full md:inline-flex"
            onClick={cycle}
          >
            <Images className="h-[17px] w-[17px]" strokeWidth={1.9} />
          </IconButton>
        )}
        <IconButton label={t('app.topbar.help')} variant="secondary" className="hidden h-9 w-9 rounded-full md:inline-flex">
          <HelpCircle className="h-[17px] w-[17px]" strokeWidth={1.9} />
        </IconButton>
        <span className="relative">
          <IconButton label={t('app.topbar.alerts')} variant="secondary" className="h-9 w-9 rounded-full">
            <Bell className="h-[17px] w-[17px]" strokeWidth={1.9} />
          </IconButton>
          <span className="pointer-events-none absolute right-2 top-2 h-[7px] w-[7px] rounded-full bg-crit ring-2 ring-surface" />
        </span>
      </div>
    </header>
  )
}
