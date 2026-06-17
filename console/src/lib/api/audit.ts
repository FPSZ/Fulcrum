/** 审计溯源 API —— 对接后端 GET /audit(列出所有会话审计链 + hash-chain 校验)。 */

import { api } from './client'

export interface AuditChainEventDTO {
  index: number
  event_type: string
  subject_id: string | null
  decision: string | null
  reason: string
  prev_hash: string
  event_hash: string
}

export interface AuditSessionDTO {
  session_id: string
  verified: boolean
  summary: string
  events: AuditChainEventDTO[]
}

export const fetchAuditSessions = () => api<AuditSessionDTO[]>('/audit')
