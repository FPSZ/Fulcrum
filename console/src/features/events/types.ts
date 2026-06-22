export type TrustLevel = 'untrusted' | 'semi' | 'trusted'
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
export type Disposition = 'block' | 'approve' | 'sanitize' | 'allow'
export type SourceType =
  | '文档'
  | '网页'
  | '用户'
  | '知识库'
  | '插件清单'
  | '工具返回'
  | '记忆'

/** 一条经过安全管线的事件(含来源归因链所需字段) */
export interface SecurityEvent {
  id: string
  time: string
  /** 原始时间戳(epoch 秒);接真后端时带,供总览按真实时间分桶。备份演示数据可缺省。 */
  ts?: number
  sess: string
  srcType: SourceType
  trust: TrustLevel
  risk: string
  tool: string
  policy: string
  level: RiskLevel
  disp: Disposition
  verified: boolean
  excerpt: string
  intent: string
  args: string
  conf: number
  derived: string
  reason: string
}
