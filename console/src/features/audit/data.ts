// 审计溯源类型 —— 结构镜像后端 /audit/{session_id}(AuditSink 的 append-only + hash-chain)。
// 数据走真后端 /audit;离线预览的演示数据经备份系统载入(public/demo-backup.json),不在此硬编码。
import { type MessageKey, t } from '@/lib/i18n'

export type Disposition = 'block' | 'approve' | 'sanitize' | 'allow'

export interface AuditEvent {
  index: number
  event_type: string
  subject_id?: string
  decision?: Disposition
  reason?: string
  prev_hash: string
  event_hash: string
}

export interface AuditSession {
  session_id: string
  verified: boolean
  scenario: string
  events: AuditEvent[]
}
// 事件类型标签经 t() 在调用时解析当前语言(故为函数而非模块级常量——常量会冻结导入时的语言)。
const EVENT_KEY: Record<string, MessageKey> = {
  request_received: 'audit.event.request_received',
  source_labeled: 'audit.event.source_labeled',
  input_detected: 'audit.event.input_detected',
  model_forwarded: 'audit.event.model_forwarded',
  tool_intent_detected: 'audit.event.tool_intent_detected',
  policy_decided: 'audit.event.policy_decided',
  tool_executed: 'audit.event.tool_executed',
  tool_blocked: 'audit.event.tool_blocked',
  tool_pending_approval: 'audit.event.tool_pending_approval',
}
/** 事件类型 → 当前语言标签;未知类型回退原始类型串。 */
export function eventLabel(eventType: string): string {
  const key = EVENT_KEY[eventType]
  return key ? t(key) : eventType
}
