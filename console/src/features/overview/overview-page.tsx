import { useEffect, useMemo, useState } from 'react'
import { motion, type Variants } from 'motion/react'
import { ArrowRight, Inbox, Info } from 'lucide-react'
import { Badge } from '@/components/ui'
import { cn } from '@/lib/utils'
import { ease } from '@/lib/motion'
import { useAuth } from '@/lib/auth'
import { useNavigateFeature } from '@/lib/nav'
import type { OverviewStats } from '@/lib/api/overview'
import type { SecurityEvent } from '../events/types'
import { Gauge, LiveChart } from './charts'
import type { OverviewStat } from './backup'
import { STAT_ICON, deriveRecent, realKpiCards, type StatTone } from './data'
import { useOverviewStats } from './use-stats'
import { useEventsFeed } from '../events/use-events'

const item: Variants = {
  initial: { opacity: 0 },
  animate: { opacity: 1, transition: { duration: 0.28, ease: ease.out } },
}
const container: Variants = {
  animate: { transition: { staggerChildren: 0.05, delayChildren: 0.02 } },
}

const TONE: Record<StatTone, { wrap: string; icon: string }> = {
  accent: { wrap: 'bg-accent/12', icon: 'text-accent' },
  crit: { wrap: 'bg-crit/12', icon: 'text-crit' },
  high: { wrap: 'bg-high/14', icon: 'text-high' },
  ok: { wrap: 'bg-ok/14', icon: 'text-ok' },
}

const BUCKETS = 15
const BUCKET_SEC = 60

/** KPI 卡(实时态:右下角显「实时」脉冲,不编造环比 delta)。 */
function StatCard({ s }: { s: OverviewStat }) {
  const Icon = STAT_ICON[s.key]
  const tone = TONE[s.tone]
  return (
    <motion.div variants={item} className="glass-card rounded-[16px] p-4 md:p-[18px]">
      <div className="flex items-center justify-between">
        <span className={cn('grid h-9 w-9 shrink-0 place-items-center rounded-[11px] md:h-[38px] md:w-[38px]', tone.wrap)}>
          <Icon className={cn('h-[18px] w-[18px] md:h-[19px] md:w-[19px]', tone.icon)} strokeWidth={1.8} />
        </span>
        <Info className="h-[15px] w-[15px] shrink-0 text-ink-mute" strokeWidth={1.7} />
      </div>
      <div className="mt-2.5 text-[13.5px] font-bold leading-snug tracking-[-0.01em] text-ink md:text-[15.5px]">
        {s.label}
      </div>
      <div className="tabnum mt-1 text-[25px] font-bold leading-none tracking-[-0.02em] text-ink md:mt-1.5 md:text-[30px]">
        {s.value}
        {s.unit && <span className="text-[16px] font-semibold text-ink-3 md:text-[18px]">{s.unit}</span>}
      </div>
      <div className="mt-2 flex items-center gap-2 text-[13px] text-ink-mute md:text-[13.5px]">
        <span className="flex items-center gap-1.5 font-semibold text-accent-ink">
          <span className="h-1.5 w-1.5 rounded-full bg-accent" style={{ animation: 'pulse-ring 2s infinite' }} />
          实时
        </span>
      </div>
    </motion.div>
  )
}

function EmptyOverview() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-5 p-10 text-center">
      <Inbox className="h-9 w-9 text-line-3" strokeWidth={1.4} />
      <div>
        <p className="text-[15px] font-semibold text-ink">暂无实时数据</p>
        <p className="mx-auto mt-1 max-w-[440px] text-[13.5px] leading-relaxed text-ink-3">
          安全网关还没有处理过任何请求。开启实时流量驱动(后端置
          <code className="mx-1 text-ink-2">FULCRUM_LIVE_FEED_ENABLED=1</code>),
          或到「网关实测」页发一条请求,这里就会显示真实的管线判定。
        </p>
      </div>
    </div>
  )
}

/** 把真实事件按 created_at 分桶成近 15 分钟每分钟一桶的计数序列(真实时序,非合成)。 */
function bucketByMinute(tsList: number[], nowMs: number): number[] {
  const endSec = nowMs / 1000
  const arr = new Array(BUCKETS).fill(0)
  for (const ts of tsList) {
    const ago = endSec - ts
    if (ago < 0) continue
    const idx = BUCKETS - 1 - Math.floor(ago / BUCKET_SEC)
    if (idx >= 0 && idx < BUCKETS) arr[idx] += 1
  }
  return arr
}

export function OverviewPage() {
  // 全实时:KPI/仪表盘来自 /overview/stats,事件表/趋势图来自 /events;无数据则诚实空态(不回退 seed)。
  const { data: stats } = useOverviewStats()
  const { data: events } = useEventsFeed()
  const evs = events ?? []
  const hasData = (stats && stats.events > 0) || evs.length > 0
  if (!hasData) return <EmptyOverview />
  return <LiveOverview stats={stats} events={evs} />
}

function LiveOverview({ stats, events }: { stats: OverviewStats | undefined; events: SecurityEvent[] }) {
  const navigate = useNavigateFeature()
  const canSeeEvents = useAuth().has('events.view')
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 2000)
    return () => clearInterval(t)
  }, [])

  // 趋势图:真实事件按分钟分桶(近 15 分钟)
  const series = useMemo(
    () => bucketByMinute(events.map((e) => e.ts ?? 0).filter((t) => t > 0), now),
    [events, now],
  )
  const windowTotal = series.reduce((a, b) => a + b, 0)

  // KPI 四卡(真实聚合)
  const cards = stats ? realKpiCards(stats) : []

  // 仪表盘:真实处置分布 → 受控率(拦截+审批+净化)/全部判定
  const dec = stats?.decisions ?? {}
  const block = dec.block ?? 0
  const approve = dec.approve ?? 0
  const sanitize = dec.sanitize ?? 0
  const allow = dec.allow ?? 0
  const totalDec = block + approve + sanitize + allow
  const held = block + approve + sanitize
  const controlRate = totalDec > 0 ? Math.round((held / totalDec) * 100) : 0

  const recent = deriveRecent(events, 7)

  return (
    <div className="h-full overflow-y-auto px-4 py-4 md:px-6 md:py-5">
      <p className="mb-5 flex items-center gap-1.5 text-[13.5px] text-ink-3 md:text-[14.5px]">
        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ok" style={{ animation: 'pulse-ring 2s infinite' }} />
        实时监测中 · 数据来自运行中的安全网关(/overview/stats · /events)
      </p>

      {/* KPI */}
      {cards.length > 0 && (
        <motion.div
          variants={container}
          initial="initial"
          animate="animate"
          className="grid grid-cols-2 gap-4 xl:grid-cols-4"
        >
          {cards.map((c) => (
            <StatCard key={c.key} s={c} />
          ))}
        </motion.div>
      )}

      {/* 趋势 + 仪表 */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="glass-card rounded-[16px] lg:col-span-2">
          <div className="flex items-start justify-between gap-4 p-[18px] pb-1">
            <div>
              <div className="text-[18px] font-extrabold tracking-[-0.02em] text-ink">网关处理量</div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="tabnum text-[28px] font-bold tracking-[-0.02em] text-ink">{windowTotal}</span>
                <span className="text-[14.5px] font-semibold text-ink-3">次 / 近 15 分钟</span>
              </div>
              <div className="mt-0.5 flex items-center gap-1.5 text-[13.5px] text-ink-mute">
                <span className="h-1.5 w-1.5 rounded-full bg-accent" style={{ animation: 'pulse-ring 2s infinite' }} />
                每 1 分一桶 · 真实事件时序
              </div>
            </div>
          </div>
          <div className="px-[18px] pb-4 pt-1">
            <LiveChart data={series} windowSec={BUCKETS * BUCKET_SEC} bucketSec={BUCKET_SEC} />
          </div>
        </div>

        <div className="glass-card rounded-[16px]">
          <div className="flex items-center justify-between p-[18px] pb-2">
            <div className="text-[18px] font-extrabold tracking-[-0.02em] text-ink">请求受控率</div>
          </div>
          <div className="flex flex-col items-center px-[18px] pb-5">
            <Gauge value={controlRate} label="拦截/审批/净化 占比" />
            <div className="mt-3.5 grid w-full grid-cols-2 gap-x-3 gap-y-1.5 text-[13.5px]">
              <span className="text-ink-2">拦截 <b className="tabnum font-bold text-crit">{block}</b></span>
              <span className="text-ink-2">审批 <b className="tabnum font-bold text-high">{approve}</b></span>
              <span className="text-ink-2">净化 <b className="tabnum font-bold text-med">{sanitize}</b></span>
              <span className="text-ink-2">放行 <b className="tabnum font-bold text-ok">{allow}</b></span>
            </div>
          </div>
        </div>
      </div>

      {/* 实时事件流(真实 /events) */}
      <div className="mt-4 glass-card overflow-hidden rounded-[16px]">
        <div className="flex items-center justify-between gap-3 px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="text-[18px] font-extrabold tracking-[-0.02em] text-ink">实时风险事件</div>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-ok/14 px-2 py-0.5 text-[12px] font-semibold text-ok">
              <span className="h-1.5 w-1.5 rounded-full bg-ok" style={{ animation: 'pulse-ring 2s infinite' }} />
              LIVE
            </span>
          </div>
        </div>
        {/* 桌面:表格 */}
        <div className="hidden overflow-x-auto md:block">
          <table className="w-full text-[14.5px]">
            <thead>
              <tr className="border-y border-line text-[13.5px] text-ink-mute">
                <th className="px-3 py-2.5 text-left font-semibold">时间</th>
                <th className="px-3 py-2.5 text-left font-semibold">来源 / 事件</th>
                <th className="px-3 py-2.5 text-left font-semibold">类型</th>
                <th className="px-3 py-2.5 text-left font-semibold">处置</th>
                <th className="px-3 py-2.5 text-left font-semibold">工具</th>
                <th className="px-3 py-2.5 text-left font-semibold">风险分</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((e) => {
                const SrcIcon = e.srcIcon
                const riskColor = e.risk > 75 ? 'bg-crit' : e.risk > 50 ? 'bg-high' : 'bg-ok'
                return (
                  <tr key={e.id} className="border-b border-line transition-colors last:border-0 hover:bg-white/55">
                    <td className="font-data px-3 py-3 text-ink-3">{e.time}</td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2.5">
                        <span className="grid h-[30px] w-[30px] shrink-0 place-items-center rounded-[9px] border border-line bg-surface-2">
                          <SrcIcon className="h-[15px] w-[15px] text-ink-2" strokeWidth={1.7} />
                        </span>
                        <span className="flex min-w-0 max-w-[420px] flex-col">
                          <span className="truncate font-semibold text-ink">{e.title || '(无摘要)'}</span>
                          <span className="text-[13px] text-ink-mute">{e.src}</span>
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-3 text-ink-2">{e.type}</td>
                    <td className="px-3 py-3">
                      <Badge tone={e.status.tone} dot>
                        {e.status.label}
                      </Badge>
                    </td>
                    <td className="px-3 py-3">
                      <span className="font-data rounded-[6px] bg-surface-2 px-2 py-0.5 text-[13px] text-ink-2">
                        {e.tool || '—'}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        <span className="h-1.5 w-10 overflow-hidden rounded-full bg-surface-2">
                          <span className={cn('block h-full rounded-full', riskColor)} style={{ width: `${e.risk}%` }} />
                        </span>
                        <b className="tabnum font-bold text-ink">{e.risk}</b>
                      </div>
                    </td>
                  </tr>
                )
              })}
              {canSeeEvents && (
                <tr
                  onClick={() => navigate('events')}
                  className="cursor-pointer border-b border-line transition-colors last:border-0 hover:bg-white/55"
                >
                  <td colSpan={6} className="px-5 py-3">
                    <span className="flex h-[41px] items-center justify-center gap-1.5 text-[14px] font-semibold text-accent-ink">
                      查看更多
                      <ArrowRight className="h-4 w-4" strokeWidth={2} />
                    </span>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* 移动端:卡片流 */}
        <div className="divide-y divide-line md:hidden">
          {recent.map((e) => {
            const SrcIcon = e.srcIcon
            const riskColor = e.risk > 75 ? 'bg-crit' : e.risk > 50 ? 'bg-high' : 'bg-ok'
            return (
              <div key={e.id} className="px-4 py-3">
                <div className="flex items-center gap-2.5">
                  <span className="grid h-[34px] w-[34px] shrink-0 place-items-center rounded-[9px] border border-line bg-surface-2">
                    <SrcIcon className="h-[16px] w-[16px] text-ink-2" strokeWidth={1.7} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[14.5px] font-semibold text-ink">{e.title || '(无摘要)'}</div>
                    <div className="truncate text-[12.5px] text-ink-mute">
                      {e.src} · {e.type}
                    </div>
                  </div>
                  <Badge tone={e.status.tone} dot>
                    {e.status.label}
                  </Badge>
                </div>
                <div className="mt-2 flex items-center gap-2.5 text-[12px] text-ink-mute">
                  <span className="font-data">{e.time}</span>
                  <span className="font-data rounded-[5px] bg-surface-2 px-1.5 py-0.5 text-ink-2">{e.tool || '—'}</span>
                  <span className="ml-auto flex items-center gap-1.5">
                    <span className="h-1.5 w-12 overflow-hidden rounded-full bg-surface-2">
                      <span className={cn('block h-full rounded-full', riskColor)} style={{ width: `${e.risk}%` }} />
                    </span>
                    <b className="tabnum font-bold text-ink">{e.risk}</b>
                  </span>
                </div>
              </div>
            )
          })}
          {canSeeEvents && (
            <button
              type="button"
              onClick={() => navigate('events')}
              className="flex w-full items-center justify-center gap-1.5 px-4 py-3 text-[14px] font-semibold text-accent-ink transition-colors hover:bg-white/55"
            >
              查看更多
              <ArrowRight className="h-4 w-4" strokeWidth={2} />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
