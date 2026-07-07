import {
  Brain,
  CornerDownLeft,
  Database,
  FileText,
  Globe,
  Package,
  User,
  type LucideIcon,
} from 'lucide-react'
import type { BadgeTone, DotTone } from '@/components/ui'
import { type MessageKey, t } from '@/lib/i18n'
import type { Disposition, RiskLevel, SourceType, TrustLevel } from './types'

// 标签经 t() 在调用时解析当前语言(故为函数而非模块级常量——常量会冻结导入时的语言)。
const DISP_KEY: Record<Disposition, MessageKey> = {
  block: 'events.disp.block',
  approve: 'events.disp.approve',
  sanitize: 'events.disp.sanitize',
  allow: 'events.disp.allow',
}
export function dispositionLabel(d: Disposition): string {
  return t(DISP_KEY[d])
}
// 顺序/色调单一真源在 @/lib/disposition(M29);此处再导出,既有 `./meta` 导入不受影响。
// 注:sanitize 色调随之从本页独有的 'info' 归一为全站口径 'med'(其余六页与总览硬编码均 'med')。
export { DISPOSITION_ORDER, DISPOSITION_TONE } from '@/lib/disposition'

const LEVEL_KEY: Record<RiskLevel, MessageKey> = {
  critical: 'events.level.critical',
  high: 'events.level.high',
  medium: 'events.level.medium',
  low: 'events.level.low',
}
export function levelLabel(l: RiskLevel): string {
  return t(LEVEL_KEY[l])
}
/** 「{等级}风险」(如「高风险」),供行内 Tooltip 与详情头使用。 */
export function levelRiskLabel(l: RiskLevel): string {
  return t('events.level_risk', { level: levelLabel(l) })
}
export const LEVEL_TONE: Record<RiskLevel, DotTone> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'ok',
}
/** 等级 → 徽标色(BadgeTone,供详情头使用) */
export const LEVEL_BADGE: Record<RiskLevel, BadgeTone> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'ok',
}
/** 行最左竖色条:按等级取色 */
export const LEVEL_BAR: Record<RiskLevel, string> = {
  critical: 'bg-crit',
  high: 'bg-high',
  medium: 'bg-med',
  low: 'bg-ok',
}

export const TRUST_LABEL: Record<TrustLevel, string> = {
  untrusted: 'untrusted',
  semi: 'semi',
  trusted: 'trusted',
}
export const TRUST_TONE: Record<TrustLevel, DotTone> = {
  untrusted: 'crit',
  semi: 'high',
  trusted: 'ok',
}

/** 来源类型 → 图标(去掉文字,用图形表意) */
export const SOURCE_ICON: Record<SourceType, LucideIcon> = {
  文档: FileText,
  网页: Globe,
  用户: User,
  知识库: Database,
  插件清单: Package,
  工具返回: CornerDownLeft,
  记忆: Brain,
}
