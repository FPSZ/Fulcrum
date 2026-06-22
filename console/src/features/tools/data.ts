// 工具网关页类型 —— 结构镜像后端工具调用管控:ToolIntent + 归因 + 评分 + 策略处置 + 执行。
// (对应 SecurityPipeline.evaluate_intent / GovRuntime 的 step:归因→评分→链→策略→沙箱执行)
// 数据走真后端 /tools/calls;离线预览的演示数据经备份系统载入(public/demo-backup.json),不在此硬编码。

export type Disposition = 'block' | 'approve' | 'sanitize' | 'allow'
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
export type Trust = 'untrusted' | 'semi' | 'trusted'

export interface ToolCall {
  id: string
  time: string
  tool: string
  args: string
  source_trust: Trust
  risk_score: number
  risk_level: RiskLevel
  attribution_confidence: number
  decision: Disposition
  rule: string | null
  executed: boolean
  reason: string
}
