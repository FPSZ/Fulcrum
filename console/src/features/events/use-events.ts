import { useQuery } from '@tanstack/react-query'
import { fetchEvents, type SecurityEventDTO } from '@/lib/api/events'
import type { RiskLevel, SecurityEvent, SourceType, TrustLevel } from './types'

/** 后端 SourceType 值 → 前端中文来源标签(未知归「用户」,筛查路径即用户输入)。 */
const SRC_MAP: Record<string, SourceType> = {
  user: '用户',
  document: '文档',
  webpage: '网页',
  retrieval: '知识库',
  memory: '记忆',
  tool_return: '工具返回',
  plugin_manifest: '插件清单',
}
const TRUST_MAP: Record<string, TrustLevel> = {
  untrusted: 'untrusted',
  semi_trusted: 'semi',
  trusted: 'trusted',
}
const LEVELS = new Set(['critical', 'high', 'medium', 'low'])
const DISPS = new Set(['block', 'approve', 'sanitize', 'allow'])

const fmtTime = (epochSec: number) =>
  new Date(epochSec * 1000).toLocaleTimeString('zh-CN', { hour12: false })

/** 后端事件 DTO → 前端 SecurityEvent(枚举值转中文/前端枚举,时间转时分秒)。 */
export function toSecurityEvent(d: SecurityEventDTO): SecurityEvent {
  return {
    id: d.id,
    time: fmtTime(d.time),
    sess: d.sess,
    srcType: SRC_MAP[d.src_type] ?? '用户',
    trust: TRUST_MAP[d.trust] ?? 'untrusted',
    risk: d.risk,
    tool: d.tool,
    policy: d.policy,
    level: (LEVELS.has(d.level) ? d.level : 'low') as RiskLevel,
    disp: (DISPS.has(d.disp) ? d.disp : 'allow') as SecurityEvent['disp'],
    verified: d.verified,
    excerpt: d.excerpt,
    intent: d.intent,
    args: d.args,
    conf: d.conf,
    derived: d.derived,
    reason: d.reason,
  }
}

/**
 * 会话事件流(接真后端)。每 15s 轮询,把审计判定点拉成事件行。
 * 无权限 / 后端不可达 → query error,调用方回退到导入备份的演示事件,不阻断纯前端预览。
 */
export function useEventsFeed() {
  return useQuery<SecurityEvent[]>({
    queryKey: ['events', 'feed'],
    queryFn: async () => (await fetchEvents()).map(toSecurityEvent),
    refetchInterval: 15_000,
  })
}
