// 审计溯源类型 —— 结构镜像后端 /audit/{session_id}(AuditSink 的 append-only + hash-chain)。
// 数据走真后端 /audit;离线预览的演示数据经备份系统载入(public/demo-backup.json),不在此硬编码。

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

export const EVENT_LABEL: Record<string, string> = {
  request_received: '收到请求',
  source_labeled: '来源打标',
  input_detected: '输入检测',
  model_forwarded: '转发模型',
  tool_intent_detected: '工具意图',
  policy_decided: '策略判定',
  tool_executed: '工具执行',
  tool_blocked: '工具阻断',
  tool_pending_approval: '挂起审批',
}
