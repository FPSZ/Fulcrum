// 审计溯源数据 —— 结构镜像后端 /audit/{session_id}(AuditSink 的 append-only + hash-chain)。
// 当前为代表性 seed;后续接 /audit API 时换数据源即可。哈希为演示用短串。

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

export const AUDIT_SESSIONS: AuditSession[] = [
  {
    session_id: 'eval-exf-01',
    verified: true,
    scenario: '间接注入:文档夹带「外发机密台账」',
    events: [
      { index: 0, event_type: 'request_received', prev_hash: 'GENESIS', event_hash: '7d8e0d' },
      { index: 1, event_type: 'source_labeled', prev_hash: '7d8e0d', event_hash: 'b74182' },
      { index: 2, event_type: 'input_detected', reason: 'injection / exfiltration 命中', prev_hash: 'b74182', event_hash: '2050e9' },
      { index: 3, event_type: 'policy_decided', decision: 'block', reason: '命中高危输入风险,已拦截不转发', prev_hash: '2050e9', event_hash: 'ab3885' },
      { index: 4, event_type: 'tool_blocked', subject_id: 'req-…a1', prev_hash: 'ab3885', event_hash: '77df65' },
    ],
  },
  {
    session_id: 'sess-chain-09',
    verified: true,
    scenario: '任务链:查公民信息 → 对外发送',
    events: [
      { index: 0, event_type: 'request_received', prev_hash: 'GENESIS', event_hash: 'c11a02' },
      { index: 1, event_type: 'tool_intent_detected', subject_id: 'citizen.query', prev_hash: 'c11a02', event_hash: 'd4f7b1' },
      { index: 2, event_type: 'policy_decided', decision: 'allow', reason: '查询单步合规', prev_hash: 'd4f7b1', event_hash: 'e8c330' },
      { index: 3, event_type: 'tool_executed', subject_id: 'citizen.query', prev_hash: 'e8c330', event_hash: 'f0aa19' },
      { index: 4, event_type: 'tool_intent_detected', subject_id: 'external.send', prev_hash: 'f0aa19', event_hash: '1b9c44' },
      { index: 5, event_type: 'policy_decided', decision: 'block', reason: 'block-exfil-chain:敏感读取→对外发送', prev_hash: '1b9c44', event_hash: '2c7e80' },
      { index: 6, event_type: 'tool_blocked', subject_id: 'external.send', prev_hash: '2c7e80', event_hash: '3da9f5' },
    ],
  },
  {
    session_id: 'sess-funds-21',
    verified: true,
    scenario: '资金发放:转人工审批',
    events: [
      { index: 0, event_type: 'request_received', prev_hash: 'GENESIS', event_hash: '90ab11' },
      { index: 1, event_type: 'tool_intent_detected', subject_id: 'funds.disburse', prev_hash: '90ab11', event_hash: 'aa12cd' },
      { index: 2, event_type: 'policy_decided', decision: 'approve', reason: 'approve-funds:发放财政补助须人工审批', prev_hash: 'aa12cd', event_hash: 'bc34ef' },
      { index: 3, event_type: 'tool_pending_approval', subject_id: 'funds.disburse', prev_hash: 'bc34ef', event_hash: 'cd56a0' },
    ],
  },
]
