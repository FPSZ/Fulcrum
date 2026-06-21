import { api, j } from '@/lib/api/client'

/** 网关处置:放行 / 净化 / 人工审核 / 拦截。 */
export type Disposition = 'allow' | 'sanitize' | 'approve' | 'block'

export interface GatewayFinding {
  kind: string
  score: number
  severity?: string | null
  source_type?: string | null
  matched: string[]
}

/** POST /gateway/chat 的真实返回:一条请求过网关的完整判定链。 */
export interface GatewayChatResult {
  session_id: string
  decision: Disposition // 输入闸门处置
  risk_level: string
  forwarded: boolean // 是否真正转发给了企业智能体
  reason: string
  max_score: number
  findings: GatewayFinding[]
  reply: string // 仅放行时为企业智能体真实回复(出口拦截时为打码占位)
  tools: Record<string, unknown>[] // 企业智能体本轮工具轨迹
  upstream_error?: string | null
  output_decision?: Disposition | null // 出口闸门处置(无回复时为 null)
  output_risk_level: string
  output_reason: string
  output_blocked: boolean
  output_sanitized: boolean
}

/** 把一条用户消息送进透明安全网关,返回真实的「输入闸门→转发→企业回复→出口闸门」判定链。 */
export const sendGatewayChat = (sessionId: string, message: string) =>
  api<GatewayChatResult>('/gateway/chat', j({ session_id: sessionId, message }))
