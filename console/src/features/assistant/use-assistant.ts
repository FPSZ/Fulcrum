import { useQuery } from '@tanstack/react-query'
import { api, j } from '@/lib/api/client'
import type {
  AssistantAction,
  AssistantTool,
  ChatResponse,
  ConfirmResponse,
  PlanResult,
  UndoResponse,
} from './data'

/**
 * 当前角色能调的动作目录(接真后端 GET /assistant/actions)。每 60s 轮询。
 * 后端按权限点过滤 —— 助手能调的动作 = 角色能点的按钮;无权限/不可达/空 → 回退演示 seed。
 */
export function useAssistantActions() {
  return useQuery<AssistantAction[]>({
    queryKey: ['assistant', 'actions'],
    queryFn: () => api<AssistantAction[]>('/assistant/actions'),
    refetchInterval: 60_000,
  })
}

/**
 * 把自然语言意图交给规划大脑(POST /assistant/plan)。后端强制 RBAC(越权直接拒)、
 * 风险分级(高危标 requires_confirmation)、并把这次规划写入审计 hash-chain。
 */
export function planIntent(intent: string): Promise<PlanResult> {
  return api<PlanResult>('/assistant/plan', j({ intent }))
}

// ─────────────────────────── 真 Agent(plan/11)──────────────────────────

/**
 * 当前角色可调的工具(GET /assistant/tools)—— 从后端操作注册表按权限派生。
 * 与 /assistant/actions 同义但面向真 Agent;不可达/未授权 → 回退演示 seed(由调用方决定)。
 */
export function useAssistantTools() {
  return useQuery<AssistantTool[]>({
    queryKey: ['assistant', 'tools'],
    queryFn: () => api<AssistantTool[]>('/assistant/tools'),
    refetchInterval: 60_000,
  })
}

/**
 * 把意图交给真 Agent(POST /assistant/chat)。读类/ui 自动编排、写类产出待确认提案,
 * 三道吃狗粮闸门 + 审计在后端强制。`session_id` 串起本次会话的对话/确认/撤销/审计。
 */
export function sendChat(message: string, sessionId: string): Promise<ChatResponse> {
  return api<ChatResponse>('/assistant/chat', j({ message, session_id: sessionId }))
}

/** 确认执行某写提案(带编辑后参数)。越权 → 后端 403。 */
export function confirmAction(
  actionToken: string,
  editedArgs: Record<string, unknown>,
  sessionId: string,
): Promise<ConfirmResponse> {
  return api<ConfirmResponse>(
    '/assistant/confirm',
    j({ action_token: actionToken, edited_args: editedArgs, session_id: sessionId }),
  )
}

/** 一键撤销某已执行写操作。越权 → 后端 403。 */
export function undoAction(actionId: string, sessionId: string): Promise<UndoResponse> {
  return api<UndoResponse>('/assistant/undo', j({ action_id: actionId, session_id: sessionId }))
}
