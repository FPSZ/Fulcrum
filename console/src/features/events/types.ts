export type TrustLevel = 'untrusted' | 'semi' | 'trusted'
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
// 处置类型单一真源在 @/lib/disposition(M29);此处再导出,页内既有 `./types` 导入不受影响。
import type { Disposition } from '@/lib/disposition'
export type { Disposition }
export type SourceType =
  | '文档'
  | '网页'
  | '用户'
  | '知识库'
  | '插件清单'
  | '工具返回'
  | '记忆'

/** 折叠行:同一会话同一判定标题的多条事件归并成一行(代表=最新一条,count=归并条数)。
 *  墙上以「一段对话 = 少数几行」呈现,点开仍能在详情重建整段对话——折叠只收展示,不丢数据。 */
export interface FoldedRow {
  rep: SecurityEvent
  count: number
  /** 桶内最严重等级(决定左侧色条),通常同级;混级时取最坏,不让高危被放行掩盖。 */
  level: RiskLevel
}

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
