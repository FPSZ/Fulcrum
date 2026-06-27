// AI 操作助手数据 —— 结构镜像后端 `adapters/assistant`(动作目录 + 规划结果)。
// 动作目录接真:GET /assistant/actions(按当前角色权限点过滤);不可达/未授权 → 回退演示 seed。
// 规划接真:POST /assistant/plan,后端强制 RBAC + 风险分级 + 写审计链。
//
// seed/回退目录与"动作 id→可执行映射"均由各 FeatureModule 的 `actions` 聚合而来
// (getModuleActions),不再集中硬编码 —— 与后端 @capability 注册动作对称:谁的页谁声明动作。

import { getModuleActions, type ModuleActionRisk } from '@/lib/module'

/** 助手页统一动效缓动(各拆分组件共用,避免各处重复定义)。 */
export const EASE = [0.25, 1, 0.5, 1] as const

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

// ─────────────────────────── 真 Agent(plan/11)·镜像后端 DTO ───────────────────────────

/** 操作面三类:ui 前端执行 / read 后端只读 / write 提案-确认-可撤销。 */
export type ToolKind = 'ui' | 'read' | 'write'

/** 当前角色可调的一个工具(镜像 AssistantToolDTO,GET /assistant/tools)。 */
export interface AssistantTool {
  name: string
  kind: ToolKind
  label: string
  description: string
  risk: ActionRisk
  requires: string[]
  reversible: boolean
}

/** 前端待执行的 ui 指令(导航/筛选/开面板)。 */
export interface UiDirective {
  tool: string
  label: string
  args: Record<string, unknown>
}

/** 一步执行轨迹(透明展示助手调了什么)。 */
export interface AssistantStep {
  tool: string
  kind: string
  label: string
  ok: boolean
  detail: string
}

/** 写操作的待确认提案(可编辑卡片)。 */
export interface ProposedAction {
  tool: string
  label: string
  risk: string
  args: Record<string, unknown>
  requires: string[]
  note: string
  action_token: string
  reversible: boolean
  before: Record<string, unknown> // 改动字段的当前值(before→after 差异)
}

/** 需管理员审批的「待发起申请」(闸判 APPROVE 时产出;不自动落工单)。 */
export interface ApprovalRequest {
  stage: 'input' | 'output'
  title: string
  reason: string
  risk_level: string
  excerpt: string
  score: number
}

/** 流式事件(SSE,镜像后端 agent.run_stream)。 */
export type StreamEvent =
  | { type: 'delta'; text: string }
  | ({ type: 'step' } & AssistantStep)
  | ({ type: 'ui' } & UiDirective)
  | ({ type: 'proposal' } & ProposedAction)
  | ({ type: 'approval' } & ApprovalRequest)
  | { type: 'done'; session_id: string; blocked: boolean; reply: string; compressed?: boolean }

/** 一次 chat 的应答(镜像 AssistantChatResponse,POST /assistant/chat)。 */
export interface ChatResponse {
  session_id: string
  reply: string
  blocked: boolean
  compressed?: boolean
  ui_directives: UiDirective[]
  proposed_actions: ProposedAction[]
  approval_requests: ApprovalRequest[]
  steps: AssistantStep[]
}

/** 确认执行应答(POST /assistant/confirm)。 */
export interface ConfirmResponse {
  ok: boolean
  summary: string
  action_id: string | null
  reversible: boolean
  undo_preview: string
  error: string | null
}

/** 撤销应答(POST /assistant/undo)。 */
export interface UndoResponse {
  ok: boolean
  summary: string
  error: string | null
}

// ─────────────────────────── 模型接入配置(本地私有化优先,三协议)───────────────────────────

/** 模型协议:OpenAI 兼容 / Ollama 原生 / Anthropic。 */
export type ModelProtocol = 'openai' | 'ollama' | 'anthropic'

/** 模型接入配置回显(镜像 AssistantModelConfigDTO;密钥掩码)。 */
export interface ModelConfig {
  protocol: ModelProtocol
  endpoint: string
  model: string
  api_key_masked: string
  api_key_set: boolean
  timeout_seconds: number
  verify_tls: boolean
  configured: boolean // 是否已显式配置完成
  ready: boolean // 是否可真正发起对话(configured + 端点/模型齐备)
}

/** 保存/测试模型配置的表单负载。api_key:undefined=保持原值,""=清空,非空=设新值。 */
export interface ModelConfigUpdate {
  protocol: ModelProtocol
  endpoint: string
  model: string
  api_key?: string | null
  timeout_seconds?: number
  verify_tls?: boolean
}

/** 测试连接结果。 */
export interface ModelTestResult {
  ok: boolean
  detail: string
  latency_ms?: number | null
}

/** ui 工具 name → 前端功能页 id(导航直达)。后端 page 枚举与功能页 id 基本同名。 */
export const PAGE_TO_FEATURE: Record<string, string> = {
  overview: 'overview',
  events: 'events',
  policies: 'policies',
  audit: 'audit',
  supply: 'supply',
  tools: 'tools',
  settings: 'settings',
  users: 'users',
}

/** 工具类别中文短名(侧栏分组 + 轨迹标签)。 */
export const KIND_LABEL: Record<ToolKind, string> = {
  ui: '界面',
  read: '查询',
  write: '操作',
}

/** 对话气泡里的一条消息(本地会话态)。 */
export type ChatMessage =
  | { id: string; role: 'user'; text: string }
  | {
      id: string
      role: 'assistant'
      text: string
      pending: boolean
      streaming: boolean
      blocked: boolean
      steps: AssistantStep[]
      proposals: ProposalState[]
      approvals: ApprovalState[]
    }

/** 审批申请在前端的发起态(包住后端申请 + 本地发起/落单结果)。 */
export interface ApprovalState {
  id: string
  request: ApprovalRequest
  status: 'idle' | 'filing' | 'filed' | 'failed'
}

/** 提案在前端的可编辑/执行态(包住后端提案 + 本地编辑参数 + 确认/撤销结果)。 */
export interface ProposalState {
  id: string
  action: ProposedAction
  editedArgs: Record<string, unknown>
  status: 'editing' | 'confirming' | 'done' | 'cancelled' | 'undoing' | 'undone'
  resultSummary: string
  actionId: string | null
  reversible: boolean
  undoPreview: string
}
