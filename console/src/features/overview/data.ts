import { ShieldCheck, ShieldAlert, Clock, FileCheck2, type LucideIcon } from 'lucide-react'
import type { BadgeTone } from '@/components/ui'
import { DISPOSITION_LABEL, DISPOSITION_TONE, SOURCE_ICON } from '../events/meta'
import type { SecurityEvent } from '../events/types'
import type { OverviewStat } from './backup'

export type StatTone = OverviewStat['tone']

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
      status: { label: DISPOSITION_LABEL[e.disp], tone: DISPOSITION_TONE[e.disp] },
      tool: e.tool,
      risk: Math.round(e.conf * 100),
    }))
}
