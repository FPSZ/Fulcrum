/**
 * 处置(Disposition)域元数据单一真源 —— 类型 + 展示顺序 + 徽标色调(M29)。
 *
 * 此前该三件套在 events/gateway/audit/policies/tools/supply/eval 七处各写一份,
 * 且已出现漂移(events 的 sanitize 色调独为 'info',其余六页与总览硬编码均为 'med')。
 * 本模块归一**跨页必须一致**的语义:值域、顺序、色调。
 *
 * 刻意不归一的:各页处置**文案**(i18n)——按语境措辞是设计而非重复
 * (gateway「转人工审核」/ supply「需复核」/ events「待审批」/ 其余「审批」),
 * 留在各页命名空间(`<ns>.disp.*` / `supply.rating.*`)。
 */
import type { BadgeTone } from '@/components/ui'

/** 与后端 core.domain.Disposition 值域一致(ScanReport.rating 亦同值域)。 */
export type Disposition = 'block' | 'approve' | 'sanitize' | 'allow'

/** 展示顺序:按处置严厉度降序(筛选器/分组统一用它,别自排)。 */
export const DISPOSITION_ORDER: Disposition[] = ['block', 'approve', 'sanitize', 'allow']

/** 处置 → 徽标色调。 */
export const DISPOSITION_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}

/** 宽入口:值来自未收窄的字符串(如评测报告 JSON)时用,未知值回退 neutral。 */
export function dispositionTone(value: string): BadgeTone {
  return DISPOSITION_TONE[value as Disposition] ?? 'neutral'
}
