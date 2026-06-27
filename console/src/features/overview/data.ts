import { ShieldCheck, ShieldAlert, Clock, FileCheck2, type LucideIcon } from 'lucide-react'
import type { BadgeTone } from '@/components/ui'
import type { OverviewStats } from '@/lib/api/overview'
import { dispositionLabel, DISPOSITION_TONE, SOURCE_ICON } from '../events/meta'
import type { SecurityEvent } from '../events/types'
import type { OverviewStat } from './backup'

export type StatTone = OverviewStat['tone']

/** 接真后端时各 KPI 卡的默认文案/色调(无备份时也能成卡;有备份则沿用其 label/unit) */
const REAL_KPI_META: Record<OverviewStat['key'], { label: string; unit?: string; tone: StatTone }> = {
  controlled: { label: '受控调用', tone: 'accent' },
  blocked: { label: '高危拦截', tone: 'crit' },
  pending: { label: '待人工研判', tone: 'high' },
  audit: { label: '审计完整率', unit: '%', tone: 'ok' },
}

const fmtInt = (n: number) => n.toLocaleString('en-US')

/**
 * 把后端实时聚合统计映射成四张 KPI 卡(覆盖备份演示值)。
 * controlled/blocked/pending 为计数;audit 为 hash-chain 校验通过率(%)。
 * base(若有备份)只用于沿用一致的 label/unit;delta 在实时态不展示,故置空。
 */
export function realKpiCards(stats: OverviewStats, base?: OverviewStat[]): OverviewStat[] {
  const rate = stats.sessions > 0 ? (stats.verified_sessions / stats.sessions) * 100 : 100
  const value: Record<OverviewStat['key'], string> = {
    controlled: fmtInt(stats.requests),
    blocked: fmtInt(stats.blocked),
    pending: String(stats.pending),
    audit: String(Math.round(rate * 10) / 10),
  }
  const keys: OverviewStat['key'][] = ['controlled', 'blocked', 'pending', 'audit']
  return keys.map((key) => {
    const meta = REAL_KPI_META[key]
    const seed = base?.find((s) => s.key === key)
    return {
      key,
      label: seed?.label ?? meta.label,
      value: value[key],
      unit: key === 'audit' ? (seed?.unit ?? meta.unit) : undefined,
      delta: '',
      dir: 'up',
      tone: seed?.tone ?? meta.tone,
    }
  })
}

/**
 * 无后端实时统计时,从导入备份的事件流派生总览聚合(口径对齐后端 /overview/stats):
 * 受控调用=事件数,高危拦截=block 数,待研判=approve 数,审计完整率=无篡改会话占比。
 * 仅用于「演示备份」预览;真实态一律以后端聚合为准。清空备份则无事件 → 上层走空态。
 */
export function statsFromEvents(events: SecurityEvent[]): OverviewStats {
  const sessions = new Set(events.map((e) => e.sess))
  const tampered = new Set(events.filter((e) => !e.verified).map((e) => e.sess))
  const decisions: Record<string, number> = {}
  const byType: Record<string, number> = {}
  for (const e of events) {
    decisions[e.disp] = (decisions[e.disp] ?? 0) + 1
    byType[e.srcType] = (byType[e.srcType] ?? 0) + 1
  }
  return {
    sessions: sessions.size,
    events: events.length,
    verified_sessions: [...sessions].filter((s) => !tampered.has(s)).length,
    requests: events.length,
    blocked: decisions.block ?? 0,
    pending: decisions.approve ?? 0,
    decisions,
    by_type: byType,
  }
}

/** KPI key → 图标(图标不入备份,前端按 key 映射) */
export const STAT_ICON: Record<OverviewStat['key'], LucideIcon> = {
  controlled: ShieldCheck,
  blocked: ShieldAlert,
  pending: Clock,
  audit: FileCheck2,
}

export interface RecentRow {
  id: string
  time: string
  title: string
  src: string
  srcIcon: LucideIcon
  type: string
  status: { label: string; tone: BadgeTone }
  tool: string
  risk: number
}

/** 从 events 资源实时派生「最近风险事件」表(按时间倒序取前 n 条) */
export function deriveRecent(events: SecurityEvent[], n = 6): RecentRow[] {
  return [...events]
    .sort((a, b) => (a.time < b.time ? 1 : -1))
    .slice(0, n)
    .map((e) => ({
      id: e.id,
      time: e.time,
      title: e.excerpt,
      src: e.srcType,
      srcIcon: SOURCE_ICON[e.srcType],
      type: e.risk,
      status: { label: dispositionLabel(e.disp), tone: DISPOSITION_TONE[e.disp] },
      tool: e.tool,
      risk: Math.round(e.conf * 100),
    }))
}
