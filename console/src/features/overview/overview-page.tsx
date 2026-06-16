import { useState } from 'react'
import { motion, type Variants } from 'motion/react'
import {
  ArrowRight,
  ArrowUp,
  ChevronDown,
  Download,
  Inbox,
  Info,
  MoreHorizontal,
  Radio,
  Search,
  SlidersHorizontal,
} from 'lucide-react'
import { Badge, Button } from '@/components/ui'
import { cn } from '@/lib/utils'
import { ease } from '@/lib/motion'
import { useAuth } from '@/lib/auth'
import { useNavigateFeature } from '@/lib/nav'
import { useResource } from '@/lib/backup'
import { ImportBackupButtons } from '../backup/import-controls'
import type { SecurityEvent } from '../events/types'
import { BarChart, Gauge, LiveChart } from './charts'
import type { OverviewData, OverviewStat } from './backup'
import { STAT_ICON, deriveRecent, type StatTone } from './data'
import { useLive } from './use-live'

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

const numBase = (v: string) => parseInt(v.replace(/[^0-9]/g, ''), 10) || 0
const fmtNum = (n: number) => n.toLocaleString('en-US')

// —— 实时区间条:对数刻度 1 分钟 ~ 3 天,滑块整数 0..1000 ——
const RANGE_MIN_S = 60
const RANGE_MAX_S = 3 * 24 * 3600
const LN_MIN = Math.log(RANGE_MIN_S)
const LN_MAX = Math.log(RANGE_MAX_S)
const sliderToSec = (v: number) => Math.exp(LN_MIN + (v / 1000) * (LN_MAX - LN_MIN))
const secToSlider = (s: number) => Math.round(((Math.log(s) - LN_MIN) / (LN_MAX - LN_MIN)) * 1000)
const DEFAULT_SLIDER = secToSlider(15 * 60) // 默认近 15 分钟

function fmtWindow(sec: number): string {
  if (sec < 3600) return `${Math.round(sec / 60)} 分钟`
  if (sec < 86400) {
    const h = sec / 3600
    return `${h < 10 ? +h.toFixed(1) : Math.round(h)} 小时`
  }
  const d = sec / 86400
  return `${d < 10 ? +d.toFixed(1) : Math.round(d)} 天`
}

/** 稳定伪随机 [0,1):同一桶索引恒得同值(随时间平移而非闪烁) */
const hash01 = (n: number) => {
  const x = Math.sin(n * 12.9898) * 43758.5453
  return x - Math.floor(x)
}
const synthBucket = (idx: number, bucketSec: number) => {
  const rate = 0.12 + 0.12 * hash01(idx * 0.37) // 平均 ~0.18 次/秒
  let v = rate * bucketSec
  if (hash01(idx * 1.7) > 0.93) v *= 2.6 // 偶发突发
  return Math.max(0, Math.round(v))
}

/** 按窗口选「nice」最小单位(桶大小):目标约 12~24 根柱,窗口越小桶越大、柱越粗 */
const NICE_BUCKETS = [
  5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400,
]
function niceBucket(windowSec: number): number {
  const target = windowSec / 18 // ~18 根柱
  for (const n of NICE_BUCKETS) if (n >= target) return n
  return NICE_BUCKETS[NICE_BUCKETS.length - 1]
}
/** 桶大小 → 中文单位(横坐标/副标题用) */
function fmtBucket(sec: number): string {
  if (sec < 60) return `${sec} 秒`
  if (sec < 3600) return `${sec / 60} 分`
  if (sec < 86400) return `${sec / 3600} 小时`
  return `${sec / 86400} 天`
}

/** 把选定窗口按 bucketSec 分桶;最右(当前)桶在 ≤60 秒桶时取真实到达,其余合成 */
function buildWindowSeries(windowSec: number, bucketSec: number, nowMs: number, perSecond: number[]): number[] {
  const count = Math.max(6, Math.round(windowSec / bucketSec))
  const nowEpoch = nowMs / 1000
  return Array.from({ length: count }, (_, j) => {
    const isCurrent = j === count - 1
    if (isCurrent && bucketSec <= 60) {
      return perSecond.slice(-Math.round(bucketSec)).reduce((a, b) => a + b, 0)
    }
    const end = nowEpoch - (count - 1 - j) * bucketSec
    return synthBucket(Math.floor(end / bucketSec), bucketSec)
  })
}

function StatCard({ s, live, deltaLabel = '较上月' }: { s: OverviewStat; live?: boolean; deltaLabel?: string }) {
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
        {live ? (
          <span className="flex items-center gap-1.5 font-semibold text-accent-ink">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" style={{ animation: 'pulse-ring 2s infinite' }} />
            实时
          </span>
        ) : (
          <>
            <span className={cn('flex items-center gap-0.5 font-bold', s.dir === 'up' ? 'text-ok' : 'text-crit')}>
              <ArrowUp className={cn('h-3.5 w-3.5', s.dir === 'down' && 'rotate-180')} strokeWidth={2.4} />
              {s.delta}
            </span>
            <span>{deltaLabel}</span>
          </>
        )}
      </div>
    </motion.div>
  )
}

function EmptyOverview() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-5 p-10 text-center">
      <Inbox className="h-9 w-9 text-line-3" strokeWidth={1.4} />
      <div>
        <p className="text-[15px] font-semibold text-ink">总览暂无数据</p>
        <p className="mx-auto mt-1 max-w-[400px] text-[13.5px] leading-relaxed text-ink-3">
          指标与事件均来自导入的备份。导入一个枢衡备份,或先载入演示备份查看完整效果。
        </p>
      </div>
      <ImportBackupButtons />
    </div>
  )
}

export function OverviewPage() {
  const ov = useResource<OverviewData>('overview')[0] as OverviewData | undefined
  const events = useResource<SecurityEvent>('events')
  if (!ov && events.length === 0) return <EmptyOverview />
  return <LiveOverview ov={ov} seed={events} />
}

/** 实时面板主体(数据流每秒推进) */
function LiveOverview({ ov, seed }: { ov?: OverviewData; seed: SecurityEvent[] }) {
  const { now, feed, freshIds, perSecond, added, pending } = useLive(seed, true)
  const [chartMode, setChartMode] = useState<'live' | 'month' | 'year'>('live')
  const [sliderVal, setSliderVal] = useState(DEFAULT_SLIDER)
  const navigate = useNavigateFeature()
  const canSeeEvents = useAuth().has('events.view')

  // 实时窗口:滑条 → 秒数(对数)→ nice 桶大小 → 分桶聚合(随 now 每秒重算 → 滚动)
  const windowSec = Math.round(sliderToSec(sliderVal))
  const windowLabel = fmtWindow(windowSec)
  const bucketSec = niceBucket(windowSec)
  const liveSeries = buildWindowSeries(windowSec, bucketSec, now.getTime(), perSecond)
  const liveTotal = liveSeries.reduce((a, b) => a + b, 0)

  // 月视图数据:按天序列(缺省时回退到年序列,保证旧备份也能渲染)
  const at = ov?.attacks
  const hasDaily = !!(at?.daily && at.days)
  const dayData = hasDaily ? at!.daily! : (at?.monthly ?? [])
  const dayLabels = hasDaily ? at!.days! : (at?.months ?? [])
  const dayPeak = hasDaily ? (at?.dailyPeakIndex ?? 0) : (at?.peakIndex ?? 0)
  const headerTotal = chartMode === 'month' ? (at?.monthTotal ?? at?.total) : at?.total
  const headerDelta = chartMode === 'month' ? (at?.monthDelta ?? at?.delta) : at?.delta

  // KPI 随时间筛选变化:年用 kpiYear;仅「实时」档在基线上叠加实时增量并跳动
  const isLive = chartMode === 'live'
  const baseStats = chartMode === 'year' && ov?.kpiYear ? ov.kpiYear : ov?.stats
  const deltaLabel = chartMode === 'year' ? '较上年' : '较上月'
  const stats: { stat: OverviewStat; live: boolean }[] =
    baseStats?.map((s) => {
      if (isLive && s.key === 'controlled')
        return { stat: { ...s, value: fmtNum(numBase(s.value) + added.controlled) }, live: true }
      if (isLive && s.key === 'blocked')
        return { stat: { ...s, value: fmtNum(numBase(s.value) + added.blocked) }, live: true }
      if (isLive && s.key === 'pending') return { stat: { ...s, value: String(pending) }, live: true }
      return { stat: s, live: false }
    }) ?? []

  const recent = deriveRecent(feed, 7)
  const RANGE: { key: 'live' | 'month' | 'year'; label: string }[] = [
    { key: 'live', label: '实时' },
    { key: 'month', label: '本月' },
    { key: 'year', label: '本年' },
  ]

  return (
    <div className="h-full overflow-y-auto px-4 py-4 md:px-6 md:py-5">
      {/* 欢迎 + 实时时钟 */}
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div>
          <h2 className="text-[20px] font-bold tracking-[-0.02em] text-ink md:text-[22px]">欢迎回来,安全运营 👋</h2>
          <p className="mt-1 flex items-center gap-1.5 text-[13.5px] text-ink-3 md:text-[14.5px]">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ok" style={{ animation: 'pulse-ring 2s infinite' }} />
            实时监测中 · 政务办公助手 英雄场景全程护航中
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2.5">
          {/* 全局时间筛选:切换后下方 KPI / 图表 / 事件全部跟随 */}
          <div className="flex items-center rounded-full border border-line bg-subtle p-0.5">
            {RANGE.map((r) => (
              <button
                key={r.key}
                onClick={() => setChartMode(r.key)}
                className={cn(
                  'flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13.5px] font-semibold transition-colors',
                  chartMode === r.key ? 'bg-ink text-white shadow-xs' : 'text-ink-3 hover:text-ink',
                )}
              >
                {r.key === 'live' && <Radio className="h-3.5 w-3.5" strokeWidth={2.2} />}
                {r.label}
              </button>
            ))}
          </div>
          <Button variant="secondary">
            <Download className="h-3.5 w-3.5" /> 导出
          </Button>
        </div>
      </div>

      {/* KPI */}
      {stats.length > 0 && (
        <motion.div
          variants={container}
          initial="initial"
          animate="animate"
          className="grid grid-cols-2 gap-4 xl:grid-cols-4"
        >
          {stats.map(({ stat, live }) => (
            <StatCard key={stat.key} s={stat} live={live} deltaLabel={deltaLabel} />
          ))}
        </motion.div>
      )}

      {/* 洞察 + 仪表 */}
      {ov && (
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="glass-card rounded-[16px] lg:col-span-2">
            <div className="flex items-start justify-between gap-4 p-[18px] pb-1">
              <div>
                <div className="text-[18px] font-extrabold tracking-[-0.02em] text-ink">攻击与阻断洞察</div>
                {chartMode === 'live' ? (
                  <>
                    <div className="mt-2 flex items-baseline gap-2">
                      <span className="tabnum text-[28px] font-bold tracking-[-0.02em] text-ink">{liveTotal}</span>
                      <span className="text-[14.5px] font-semibold text-ink-3">次 / 近 {windowLabel}</span>
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 text-[13.5px] text-ink-mute">
                      <span className="h-1.5 w-1.5 rounded-full bg-accent" style={{ animation: 'pulse-ring 2s infinite' }} />
                      每 {fmtBucket(bucketSec)}一桶 · 共 {liveSeries.length} 桶滚动
                    </div>
                  </>
                ) : (
                  <>
                    <div className="mt-2 flex items-baseline gap-2">
                      <span className="tabnum text-[28px] font-bold tracking-[-0.02em] text-ink">{headerTotal}</span>
                      <span
                        className={cn(
                          'flex items-center gap-0.5 text-[14.5px] font-bold',
                          ov.attacks.dir === 'up' ? 'text-ok' : 'text-crit',
                        )}
                      >
                        <ArrowUp className={cn('h-3.5 w-3.5', ov.attacks.dir === 'down' && 'rotate-180')} strokeWidth={2.4} />
                        {headerDelta}
                      </span>
                    </div>
                    <div className="mt-0.5 text-[13.5px] text-ink-mute">
                      {chartMode === 'month' ? '本月累计攻击尝试' : '本年累计攻击尝试'}
                    </div>
                  </>
                )}
              </div>
              <div className="flex gap-3.5 pt-1 text-[13.5px] text-ink-3">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-[3px] bg-bar-idle" /> {chartMode === 'live' ? '历史秒' : '攻击尝试'}
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-[3px] bg-accent" />{' '}
                  {chartMode === 'live' ? '当前秒' : chartMode === 'month' ? '峰值日' : '峰值月份'}
                </span>
              </div>
            </div>
            <div className="px-[18px] pb-3 pt-1">
              {chartMode === 'live' ? (
                <LiveChart data={liveSeries} windowSec={windowSec} bucketSec={bucketSec} />
              ) : chartMode === 'month' ? (
                <BarChart data={dayData} labels={dayLabels} highlight={dayPeak} />
              ) : (
                <BarChart data={ov.attacks.monthly} labels={ov.attacks.months} highlight={ov.attacks.peakIndex} />
              )}
            </div>

            {/* 实时区间条:无极调节 1 分钟 ~ 3 天 */}
            {chartMode === 'live' && (
              <div className="px-[18px] pb-4 pt-0.5">
                <div className="mb-1.5 flex items-center justify-between text-[12.5px]">
                  <span className="text-ink-mute">1 分钟</span>
                  <span className="font-semibold text-accent-ink">近 {windowLabel}</span>
                  <span className="text-ink-mute">3 天</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1000}
                  step={1}
                  value={sliderVal}
                  onChange={(e) => setSliderVal(Number(e.target.value))}
                  aria-label="实时区间"
                  className="range-live w-full"
                  style={{
                    background: `linear-gradient(to right, var(--color-accent) ${sliderVal / 10}%, var(--color-surface-2) ${sliderVal / 10}%)`,
                  }}
                />
              </div>
            )}
          </div>

          <div className="glass-card rounded-[16px]">
            <div className="flex items-center justify-between p-[18px] pb-2">
              <div className="text-[18px] font-extrabold tracking-[-0.02em] text-ink">防护成功率</div>
              <button className="focus-ring grid h-7 w-7 place-items-center rounded-[8px] text-ink-mute hover:bg-surface-2">
                <MoreHorizontal className="h-4 w-4" />
              </button>
            </div>
            <div className="flex flex-col items-center px-[18px] pb-5">
              <Gauge value={ov.protection.rate} label="阻断成功率" />
              <div className="mt-3.5 flex w-full items-center justify-between text-[14px]">
                <span className="text-ink-2">
                  已拦截 <b className="tabnum font-bold text-ink">{(ov.protection.blocked + added.blocked).toLocaleString()}</b>
                </span>
                <span className="text-ink-2">
                  目标 <b className="tabnum font-bold text-ink">{ov.protection.target.toLocaleString()}</b>
                </span>
              </div>
              <div className="mt-2.5 h-2 w-full overflow-hidden rounded-full bg-surface-2">
                <div
                  className="h-full rounded-full bg-accent transition-[width] duration-700"
                  style={{ width: `${Math.min(100, ((ov.protection.blocked + added.blocked) / ov.protection.target) * 100)}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 实时事件流 */}
      <div className="mt-4 glass-card overflow-hidden rounded-[16px]">
        <div className="flex items-center justify-between gap-3 px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="text-[18px] font-extrabold tracking-[-0.02em] text-ink">
              {chartMode === 'live' ? '实时风险事件' : chartMode === 'month' ? '本月风险事件' : '本年风险事件'}
            </div>
            {chartMode === 'live' && (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-ok/14 px-2 py-0.5 text-[12px] font-semibold text-ok">
                <span className="h-1.5 w-1.5 rounded-full bg-ok" style={{ animation: 'pulse-ring 2s infinite' }} />
                LIVE
              </span>
            )}
          </div>
          <div className="flex items-center gap-2.5">
            <span className="hidden h-8 items-center gap-2 rounded-[10px] border border-line bg-surface/70 px-3 text-[14px] text-ink-mute sm:flex">
              <Search className="h-3.5 w-3.5" /> 检索
            </span>
            <Button variant="secondary" size="sm" className="hidden sm:inline-flex">
              全部类型 <ChevronDown className="h-3.5 w-3.5 opacity-60" />
            </Button>
            <Button variant="secondary" size="sm">
              <SlidersHorizontal className="h-3.5 w-3.5" /> 筛选
            </Button>
          </div>
        </div>
        {/* 桌面:表格 */}
        <div className="hidden overflow-x-auto md:block">
          <table className="w-full text-[14.5px]">
            <thead>
              <tr className="border-y border-line text-[13.5px] text-ink-mute">
                <th className="w-9 px-5 py-2.5" />
                <th className="px-3 py-2.5 text-left font-semibold">事件号</th>
                <th className="px-3 py-2.5 text-left font-semibold">时间</th>
                <th className="px-3 py-2.5 text-left font-semibold">来源 / 事件</th>
                <th className="px-3 py-2.5 text-left font-semibold">类型</th>
                <th className="px-3 py-2.5 text-left font-semibold">状态</th>
                <th className="px-3 py-2.5 text-left font-semibold">工具</th>
                <th className="px-3 py-2.5 text-left font-semibold">风险分</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((e) => {
                const SrcIcon = e.srcIcon
                const riskColor = e.risk > 75 ? 'bg-crit' : e.risk > 50 ? 'bg-high' : 'bg-ok'
                return (
                  <tr
                    key={e.id}
                    className={cn(
                      'cursor-pointer border-b border-line transition-colors last:border-0 hover:bg-white/55',
                      freshIds.has(e.id) && 'row-flash',
                    )}
                  >
                    <td className="px-5 py-3">
                      <span className="block h-4 w-4 rounded-[5px] border-[1.5px] border-line-2 bg-surface/60" />
                    </td>
                    <td className="font-data px-3 py-3 text-ink-3">{e.id}</td>
                    <td className="font-data px-3 py-3 text-ink-3">{e.time}</td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2.5">
                        <span className="grid h-[30px] w-[30px] shrink-0 place-items-center rounded-[9px] border border-line bg-surface-2">
                          <SrcIcon className="h-[15px] w-[15px] text-ink-2" strokeWidth={1.7} />
                        </span>
                        <span className="flex min-w-0 max-w-[340px] flex-col">
                          <span className="truncate font-semibold text-ink">{e.title}</span>
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
                        {e.tool}
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
                  <td colSpan={8} className="px-5 py-3">
                    <span className="flex h-[42px] items-center justify-center gap-1.5 text-[14px] font-semibold text-accent-ink">
                      查看更多
                      <ArrowRight className="h-4 w-4" strokeWidth={2} />
                    </span>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* 移动端:卡片流(不横滑) */}
        <div className="divide-y divide-line md:hidden">
          {recent.map((e) => {
            const SrcIcon = e.srcIcon
            const riskColor = e.risk > 75 ? 'bg-crit' : e.risk > 50 ? 'bg-high' : 'bg-ok'
            return (
              <div key={e.id} className={cn('px-4 py-3', freshIds.has(e.id) && 'row-flash')}>
                <div className="flex items-center gap-2.5">
                  <span className="grid h-[34px] w-[34px] shrink-0 place-items-center rounded-[9px] border border-line bg-surface-2">
                    <SrcIcon className="h-[16px] w-[16px] text-ink-2" strokeWidth={1.7} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[14.5px] font-semibold text-ink">{e.title}</div>
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
                  <span className="font-data rounded-[5px] bg-surface-2 px-1.5 py-0.5 text-ink-2">{e.tool}</span>
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
