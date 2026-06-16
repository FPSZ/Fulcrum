import { useEffect, useMemo, useState } from 'react'
import { Activity, Clock, Download, Inbox, Plus, SlidersHorizontal } from 'lucide-react'
import { Button, EmptyState, Segmented, toast } from '@/components/ui'
import { useResource } from '@/lib/backup'
import { useMediaQuery } from '@/lib/use-media-query'
import { cn } from '@/lib/utils'
import { ImportBackupButtons } from '../backup/import-controls'
import { EventDetail } from './event-detail'
import { EventGroup } from './event-group'
import { DISPOSITION_ORDER, LEVEL_LABEL } from './meta'
import type { Disposition, RiskLevel, SecurityEvent } from './types'

type Filter = 'all' | RiskLevel
const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'critical', label: LEVEL_LABEL.critical },
  { value: 'high', label: LEVEL_LABEL.high },
  { value: 'medium', label: LEVEL_LABEL.medium },
]

export function EventsPage() {
  const events = useResource<SecurityEvent>('events')
  // 列表+详情并排放不下时(≤1080)切换为栈式:列表 ↔ 全屏详情
  const compact = useMediaQuery('(max-width: 1080px)')
  const [filter, setFilter] = useState<Filter>('all')
  const [collapsed, setCollapsed] = useState<Set<Disposition>>(new Set())
  const [selectedId, setSelectedId] = useState('')

  const items = useMemo(
    () => events.filter((e) => filter === 'all' || e.level === filter),
    [events, filter],
  )
  const groups = useMemo(
    () =>
      DISPOSITION_ORDER.map((disp) => ({
        disp,
        rows: items.filter((e) => e.disp === disp),
      })).filter((g) => g.rows.length > 0),
    [items],
  )
  /** 当前可见(未折叠)的事件顺序,用于上下条导航 */
  const ordered = useMemo(
    () => groups.flatMap((g) => (collapsed.has(g.disp) ? [] : g.rows.map((r) => r.id))),
    [groups, collapsed],
  )

  const counts = useMemo<Record<Filter, number>>(
    () => ({
      all: events.length,
      critical: events.filter((e) => e.level === 'critical').length,
      high: events.filter((e) => e.level === 'high').length,
      medium: events.filter((e) => e.level === 'medium').length,
      low: events.filter((e) => e.level === 'low').length,
    }),
    [events],
  )

  // 筛选后若选中项不可见,宽屏回退到第一条;窄屏不自动选(先停在列表,点了才进详情)
  useEffect(() => {
    if (compact) return
    if (!items.some((e) => e.id === selectedId)) setSelectedId(items[0]?.id ?? '')
  }, [items, selectedId, compact])

  // 选中被篡改事件 → 错误 toast
  useEffect(() => {
    const e = events.find((x) => x.id === selectedId)
    if (e && !e.verified) {
      toast.error('审计链校验失败', {
        description: `会话 ${e.sess} 的事件哈希与链不一致,疑似篡改,已锁定并上报。`,
      })
    }
  }, [selectedId, events])

  // 键盘 j/k 或 ↑↓ 翻条,审批不离手
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.target instanceof HTMLInputElement) return
      const idx = ordered.indexOf(selectedId)
      if ((ev.key === 'j' || ev.key === 'ArrowDown') && idx < ordered.length - 1) {
        ev.preventDefault()
        setSelectedId(ordered[idx + 1])
      }
      if ((ev.key === 'k' || ev.key === 'ArrowUp') && idx > 0) {
        ev.preventDefault()
        setSelectedId(ordered[idx - 1])
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [ordered, selectedId])

  const selected = events.find((e) => e.id === selectedId) ?? null
  const idx = ordered.indexOf(selectedId)

  const toggleGroup = (disp: Disposition) =>
    setCollapsed((prev) => {
      const next = new Set(prev)
      next.has(disp) ? next.delete(disp) : next.add(disp)
      return next
    })

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {events.length === 0 ? (
        /* 空态:引导导入备份 */
        <div className="flex flex-1 flex-col items-center justify-center gap-5 p-10 text-center">
          <Inbox className="h-8 w-8 text-line-3" strokeWidth={1.4} />
          <div>
            <p className="text-[16px] font-medium text-ink">还没有数据</p>
            <p className="mx-auto mt-1 max-w-[360px] text-[14.5px] leading-relaxed text-ink-3">
              事件数据来自导入的备份文件。导入一个枢衡备份,或先载入演示备份查看效果。
            </p>
          </div>
          <ImportBackupButtons />
        </div>
      ) : (
      /* 下方:左清单 + 右详情(移动端:选中后详情全屏接管,列表隐藏) */
      <div className="flex min-h-0 flex-1">
        <div className={cn('flex min-w-0 flex-1 flex-col', compact && selected && 'hidden')}>
          {/* 工具条 */}
          <div className="flex h-12 shrink-0 items-center gap-2 overflow-x-auto border-b border-line px-4 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
            <button
              type="button"
              className="focus-ring inline-flex shrink-0 items-center gap-1.5 rounded-sm border border-dashed border-line-2 px-2.5 py-1 text-[14px] text-ink-3 transition-colors hover:border-line-3 hover:text-ink-2"
            >
              <Plus className="h-3.5 w-3.5" /> 筛选
            </button>
            <Segmented
              value={filter}
              onValueChange={(v) => setFilter(v as Filter)}
              items={FILTERS.map((f) => ({ ...f, count: counts[f.value] }))}
            />
            <div className="ml-auto flex shrink-0 items-center gap-2 pl-2">
              <Button variant="ghost" size="sm" className="max-[1440px]:hidden">
                <SlidersHorizontal className="h-3.5 w-3.5" /> 分组:处置
              </Button>
              <span className="mx-0.5 h-4 w-px bg-line max-[1440px]:hidden" />
              <Button variant="ghost" size="sm" className="max-[1280px]:hidden">
                <Clock className="h-3.5 w-3.5" /> 近 24 小时
              </Button>
              <Button variant="primary" size="sm">
                <Download className="h-3.5 w-3.5" /> 导出报告
              </Button>
            </div>
          </div>

          {/* 分组清单:每组一张柔性卡片浮在磨砂桌面上(软扁平 = 卡片承托 + 内部密集行) */}
          <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto px-3 py-3">
            {groups.map((g) => (
              <EventGroup
                key={g.disp}
                disp={g.disp}
                rows={g.rows}
                collapsed={collapsed.has(g.disp)}
                selectedId={selectedId}
                onToggle={() => toggleGroup(g.disp)}
                onSelect={setSelectedId}
              />
            ))}
          </div>
        </div>

        {selected ? (
          <EventDetail
            event={selected}
            index={idx}
            total={ordered.length}
            onBack={compact ? () => setSelectedId('') : undefined}
            onPrev={idx > 0 ? () => setSelectedId(ordered[idx - 1]) : undefined}
            onNext={
              idx >= 0 && idx < ordered.length - 1
                ? () => setSelectedId(ordered[idx + 1])
                : undefined
            }
          />
        ) : (
          /* 桌面空态侧栏;移动端无选中时不渲染(列表占满) */
          <aside className="hidden w-[640px] shrink-0 border-l border-white/50 bg-white/48 backdrop-blur-xl min-[1081px]:flex max-[1440px]:w-[560px] max-[1200px]:w-[480px]">
            <EmptyState icon={Activity} title="未选中事件" hint="从左侧清单选择一条以查看证据归因链" />
          </aside>
        )}
      </div>
      )}
    </div>
  )
}
