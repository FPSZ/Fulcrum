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
import type { Disposition, RiskLevel, SourceType, TrustLevel } from './types'

export const DISPOSITION_LABEL: Record<Disposition, string> = {
  block: '阻断',
  approve: '待审批',
  sanitize: '净化',
  allow: '放行',
}
export const DISPOSITION_ORDER: Disposition[] = ['block', 'approve', 'sanitize', 'allow']
export const DISPOSITION_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'info',
  allow: 'ok',
}

export const LEVEL_LABEL: Record<RiskLevel, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
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
