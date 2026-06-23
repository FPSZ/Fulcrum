import { useCallback, useEffect, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Activity, Clock, Download, Inbox, Plus, SlidersHorizontal } from 'lucide-react'
import { Button, EmptyState, Segmented, toast } from '@/components/ui'
import { resolveEvent } from '@/lib/api/events'
import { useAuth } from '@/lib/auth'
import { useResource } from '@/lib/backup'
import { useMediaQuery } from '@/lib/use-media-query'
import { cn } from '@/lib/utils'
import { ImportBackupButtons } from '../backup/import-controls'
import { EventDetail } from './event-detail'
import { EventGroup } from './event-group'
import { DISPOSITION_ORDER, LEVEL_LABEL } from './meta'
import type { Disposition, FoldedRow, RiskLevel, SecurityEvent } from './types'
import { useEventsFeed } from './use-events'

type Filter = 'all' | RiskLevel
const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'critical', label: LEVEL_LABEL.critical },
  { value: 'high', label: LEVEL_LABEL.high },
  { value: 'medium', label: LEVEL_LABEL.medium },
]

const LEVEL_RANK: Record<RiskLevel, number> = { critical: 3, high: 2, medium: 1, low: 0 }

/**
 * 按「会话 + 判定标题」折叠成行 —— 一段多轮对话(我们的助手或接入的任意外部 agent)
 * 不再在墙上铺一长串长得一样的「正常输入放行 / 回复放行」。代表取桶内最新一条;
 * 输入已是最新在前,故每个 key 首次出现即最新,Map 保序即按代表时间倒序。
 */
function foldBySession(rows: SecurityEvent[]): FoldedRow[] {
  const buckets = new Map<string, SecurityEvent[]>()
  for (const e of rows) {
    const key = `${e.sess}|${e.risk}`
    const arr = buckets.get(key)
    if (arr) arr.push(e)
    else buckets.set(key, [e])
  }
  return Array.from(buckets.values(), (arr) => ({
    rep: arr[0],
    count: arr.length,
    level: arr.reduce<RiskLevel>((w, e) => (LEVEL_RANK[e.level] > LEVEL_RANK[w] ? e.level : w), 'low'),
  }))
}

export function EventsPage() {
  // 接真后端:有真实事件则用真;无权限/不可达/空 → 回退导入备份的演示事件(纯前端预览不受影响)。
  const backup = useResource<SecurityEvent>('events')
  const { data: live } = useEventsFeed()
  const isLive = !!(live && live.length > 0)
  const events = isLive ? live : backup
  const qc = useQueryClient()
  const { has } = useAuth()
  // 处置(批准放行/维持阻断)= 写操作:需 events.handle,且仅对真实后端事件生效(演示备份无后端)
  const canHandle = has('events.handle') && isLive
  const [resolving, setResolving] = useState<'allow' | 'block' | null>(null)
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
        rows: foldBySession(items.filter((e) => e.disp === disp)),
      })).filter((g) => g.rows.length > 0),
    [items],
  )
  /** 当前可见(未折叠)的代表事件顺序,用于上下条导航 */
  const ordered = useMemo(
    () => groups.flatMap((g) => (collapsed.has(g.disp) ? [] : g.rows.map((r) => r.rep.id))),
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
  // 同会话的全部事件 → 供详情页重建用户↔AI对话(真实数据,非编造)
  const sessionEvents = useMemo(
    () => (selected ? events.filter((x) => x.sess === selected.sess) : []),
    [events, selected],
  )

  const toggleGroup = (disp: Disposition) =>
    setCollapsed((prev) => {
      const next = new Set(prev)
      next.has(disp) ? next.delete(disp) : next.add(disp)
      return next
    })

  // 处置待审批:批准放行 / 维持阻断 → 后端落处置判定点;成功后刷新事件流(原工单隐去,代以结果行)。
  const resolve = useCallback(
    async (decision: 'allow' | 'block') => {
      if (!selected) return
      setResolving(decision)
      try {
        await resolveEvent(selected.id, decision)
        toast.success(decision === 'allow' ? '已批准放行' : '已维持阻断', {
          description: '处置已记入审计链,该待审批项已结案。',
        })
        await qc.invalidateQueries({ queryKey: ['events', 'feed'] })
      } catch (err) {
        toast.error('处置失败', { description: (err as Error).message })
      } finally {
        setResolving(null)
      }
    },
    [selected, qc],
  )

  return (
    // 事件页是实时处置工作面:其内部滚动(清单/详情各自独立)不牵动底部页脚
    <div className="flex min-h-0 flex-1 flex-col" data-no-reveal>
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
            conversation={sessionEvents}
            onResolve={resolve}
            resolving={resolving}
            canHandle={canHandle}
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
