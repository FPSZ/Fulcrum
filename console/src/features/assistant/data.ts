// AI 操作助手数据 —— 结构镜像后端 `adapters/assistant`(动作目录 + 规划结果)。
// 动作目录接真:GET /assistant/actions(按当前角色权限点过滤);不可达/未授权 → 回退演示 seed。
// 规划接真:POST /assistant/plan,后端强制 RBAC + 风险分级 + 写审计链。

/** 风险分级(后端 catalog 原值):只读可自动执行;一般需留意;高危必须二次确认。 */
export type ActionRisk = 'read_only' | 'normal' | 'high'

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
 * 动作 id → 前端功能模块 id。只读导航/筛选类动作可由本面板**直接执行**(切到对应页);
 * 不在表内的(如 policy.disable 写操作)执行入口排后,仍需操作员在该页命中受 RBAC 守卫的端点。
 */
export const ACTION_NAV: Record<string, string> = {
  'nav.overview': 'overview',
  'nav.events': 'events',
  'nav.policies': 'policies',
  'nav.audit': 'audit',
  'nav.supply': 'supply',
  'nav.tools': 'tools',
  'filter.events': 'events',
}

/** 该动作是否可由面板直接执行(只读导航/筛选)。 */
export const isExecutable = (actionId: string | null): boolean =>
  !!actionId && actionId in ACTION_NAV

export const RISK_LABEL: Record<ActionRisk, string> = {
  read_only: '只读',
  normal: '一般',
  high: '高危',
}

/** 演示用动作目录 —— 镜像后端 DEFAULT_CATALOG,后端不可达/未授权时回退展示。 */
export const SEED_ACTIONS: AssistantAction[] = [
  {
    id: 'nav.overview',
    label: '打开安全总览',
    description: '导航到安全总览页(KPI + 实时事件概览)',
    risk: 'read_only',
    requires: ['overview.view'],
    args_hint: '',
  },
  {
    id: 'nav.events',
    label: '打开实时事件',
    description: '导航到实时事件页(逐条安全事件与证据链)',
    risk: 'read_only',
    requires: ['events.view'],
    args_hint: '',
  },
  {
    id: 'nav.policies',
    label: '打开策略中心',
    description: '导航到策略中心页(当前装配的策略规则)',
    risk: 'read_only',
    requires: ['policies.view'],
    args_hint: '',
  },
  {
    id: 'nav.audit',
    label: '打开审计溯源',
    description: '导航到审计溯源页(会话 hash-chain)',
    risk: 'read_only',
    requires: ['audit.view'],
    args_hint: '',
  },
  {
    id: 'nav.supply',
    label: '打开供应链',
    description: '导航到供应链组件扫描页',
    risk: 'read_only',
    requires: ['supply.view'],
    args_hint: '',
  },
  {
    id: 'nav.tools',
    label: '打开工具网关',
    description: '导航到工具调用治理页',
    risk: 'read_only',
    requires: ['tools.view'],
    args_hint: '',
  },
  {
    id: 'filter.events',
    label: '筛选实时事件',
    description: '在实时事件页按处置或严重度筛选',
    risk: 'read_only',
    requires: ['events.view'],
    args_hint: '可选 {"disposition":"block|approve|allow","level":"low|medium|high|critical"}',
  },
  {
    id: 'policy.disable',
    label: '停用策略',
    description: '临时停用一条安全策略规则(高危:会削弱防护,必须二次确认)',
    risk: 'high',
    requires: ['policies.manage'],
    args_hint: '形如 {"policy_id":"POL-014"}',
  },
]

/** 快捷示例意图(点选即填入输入框)。 */
export const SAMPLE_INTENTS = [
  '帮我打开安全总览',
  '只看被阻断的实时事件',
  '临时停用策略 POL-014',
]
