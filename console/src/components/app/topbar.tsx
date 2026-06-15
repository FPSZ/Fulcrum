import { useEffect, useState } from 'react'
import { Bell, HelpCircle, Images, Radio, Search } from 'lucide-react'
import { IconButton, Kbd } from '@/components/ui'
import { BACKGROUNDS, useBackground } from '@/lib/background'

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
 * 全局顶栏:左侧当前区域标题,右侧实时时钟 + 全局检索 + 切换背景(多于一张时) / 帮助 / 告警。
 * 头像不放这里 —— 左下角侧栏已有用户区。
 */
export function Topbar({ title }: { title: string }) {
  const { current, cycle } = useBackground()
  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line pl-6 pr-4">
      <h1 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">{title}</h1>

      <div className="ml-auto flex items-center gap-2">
        <LiveClock />
        <button
          type="button"
          className="focus-ring flex h-9 w-[260px] max-w-[34vw] items-center gap-2 rounded-[11px] border border-line bg-surface/70 px-3 text-[14.5px] text-ink-mute transition-colors hover:border-line-2"
        >
          <Search className="h-[15px] w-[15px] shrink-0" strokeWidth={1.9} />
          <span className="truncate">检索事件 / 会话 / trace_id…</span>
          <Kbd className="ml-auto">⌘K</Kbd>
        </button>
        {BACKGROUNDS.length > 1 && (
          <IconButton
            label={`切换背景 · ${current.name}`}
            variant="secondary"
            className="h-9 w-9 rounded-full"
            onClick={cycle}
          >
            <Images className="h-[17px] w-[17px]" strokeWidth={1.9} />
          </IconButton>
        )}
        <IconButton label="帮助" variant="secondary" className="h-9 w-9 rounded-full">
          <HelpCircle className="h-[17px] w-[17px]" strokeWidth={1.9} />
        </IconButton>
        <span className="relative">
          <IconButton label="告警" variant="secondary" className="h-9 w-9 rounded-full">
            <Bell className="h-[17px] w-[17px]" strokeWidth={1.9} />
          </IconButton>
          <span className="pointer-events-none absolute right-2 top-2 h-[7px] w-[7px] rounded-full bg-crit ring-2 ring-surface" />
        </span>
      </div>
    </header>
  )
}
