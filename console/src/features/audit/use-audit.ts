import { useQuery } from '@tanstack/react-query'
import { fetchAuditSessions, type AuditSessionDTO } from '@/lib/api/audit'
import type { AuditSession, Disposition } from './data'

const DISPS = new Set<Disposition>(['block', 'approve', 'sanitize', 'allow'])

/** 后端审计会话 DTO → 前端 AuditSession(summary→scenario,decision 收窄,null→undefined)。 */
export function toAuditSession(d: AuditSessionDTO): AuditSession {
  return {
    session_id: d.session_id,
    verified: d.verified,
    scenario: d.summary,
    events: d.events.map((e) => ({
      index: e.index,
      event_type: e.event_type,
      subject_id: e.subject_id ?? undefined,
      decision: e.decision && DISPS.has(e.decision as Disposition)
        ? (e.decision as Disposition)
        : undefined,
      reason: e.reason || undefined,
      prev_hash: e.prev_hash,
      event_hash: e.event_hash,
    })),
  }
}

/**
 * 审计溯源会话列表(接真后端)。每 15s 轮询;无权限/不可达/空 → 调用方回退演示 seed。
 */
export function useAuditSessions() {
  return useQuery<AuditSession[]>({
    queryKey: ['audit', 'sessions'],
    queryFn: async () => (await fetchAuditSessions()).map(toAuditSession),
    refetchInterval: 15_000,
  })
}
