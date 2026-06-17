/** 安全总览统计 API —— 对接后端 GET /overview/stats(审计链实时聚合)。 */

import { api } from './client'

/** 后端 OverviewStatsResponse 的镜像:KPI 计数全部来自 hash-chain 审计事件。 */
export interface OverviewStats {
  sessions: number
  events: number
  verified_sessions: number
  requests: number
  blocked: number
  pending: number
  decisions: Record<string, number>
  by_type: Record<string, number>
}

export const fetchOverviewStats = () => api<OverviewStats>('/overview/stats')
