// AI 操作助手数据 —— 结构镜像后端 `adapters/assistant`(动作目录 + 规划结果)。
// 动作目录接真:GET /assistant/actions(按当前角色权限点过滤);不可达/未授权 → 回退演示 seed。
// 规划接真:POST /assistant/plan,后端强制 RBAC + 风险分级 + 写审计链。
//
// seed/回退目录与"动作 id→可执行映射"均由各 FeatureModule 的 `actions` 聚合而来
// (getModuleActions),不再集中硬编码 —— 与后端 @capability 注册动作对称:谁的页谁声明动作。

import { getModuleActions, type ModuleActionRisk } from '@/lib/module'

/** 风险分级(后端 catalog 原值):只读可自动执行;一般需留意;高危必须二次确认。 */
export type ActionRisk = ModuleActionRisk

/** 动作目录条目(镜像后端 AssistantActionDTO)。 */
export interface AssistantAction {
  id: string
  label: string
  description: string
  risk: ActionRisk
  requires: string[]
  args_hint: string
}

/** 规划结果(镜像后端 AssistantPlanResponse):选了哪个动作、是否准许、是否需二次确认、为什么。 */
export interface PlanResult {
  ok: boolean
  reason: string
  action_id: string | null
  label: string
  args: Record<string, unknown>
  risk: string
  requires_confirmation: boolean
  denied: boolean
}

/**
 * 动作 id → 前端功能模块 id 的可执行映射(由各模块 `actions` 的 `navTo` 聚合)。
 * 只读导航/筛选类动作可由本面板**直接执行**(切到对应页);无 navTo 的(如 policy.disable
 * 写操作)执行入口排后,仍需操作员在该页命中受 RBAC 守卫的端点。
 */
export function actionNav(): Record<string, string> {
  const map: Record<string, string> = {}
  for (const a of getModuleActions()) if (a.navTo) map[a.id] = a.navTo
  return map
}

/** 该动作是否可由面板直接执行(只读导航/筛选)。 */
export const isExecutable = (actionId: string | null): boolean =>
  !!actionId && actionId in actionNav()

export const RISK_LABEL: Record<ActionRisk, string> = {
  read_only: '只读',
  normal: '一般',
  high: '高危',
}

/**
 * 演示用动作目录(seed/回退)—— 由各 FeatureModule 的 `actions` 聚合而来(注册即接入),
 * 后端不可达/未授权时回退展示。形态镜像后端 AssistantActionDTO(args_hint 统一为字符串)。
 */
export function seedActions(): AssistantAction[] {
  return getModuleActions().map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
    risk: a.risk,
    requires: a.requires,
    args_hint: a.argsHint ?? '',
  }))
}

/** 快捷示例意图(点选即填入输入框)。 */
export const SAMPLE_INTENTS = [
  '帮我打开安全总览',
  '只看被阻断的实时事件',
  '临时停用策略 POL-014',
]
