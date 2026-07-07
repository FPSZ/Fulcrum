import { useQuery } from '@tanstack/react-query'
import { api, j } from '@/lib/api/client'
import { t } from '@/lib/i18n'
import type {
  ApprovalRequest,
  AssistantAction,
  AssistantTool,
  ChatResponse,
  ConfirmResponse,
  ModelConfig,
  ModelConfigUpdate,
  ModelTestResult,
  PlanResult,
  StreamEvent,
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

/**
 * 发起审批申请:把某条 APPROVE 判定落成真·待审批工单(进实时事件·待审批)。
 * 只有操作员显式点「发起申请」才调用 —— 闸门判待审不自动落单,避免无效审批堆积。
 */
export function requestApproval(req: ApprovalRequest, sessionId: string): Promise<{ ok: boolean }> {
  return api<{ ok: boolean }>(
    '/assistant/request-approval',
    j({
      session_id: sessionId,
      stage: req.stage,
      reason: req.reason,
      risk_level: req.risk_level,
      excerpt: req.excerpt,
      score: req.score,
    }),
  )
}

// ─────────────────────────── 模型接入配置(三协议 + 本地私有化)───────────────────────────

/**
 * 当前模型接入配置(GET /assistant/model-config;密钥掩码)。前端据 `ready` 决定:
 * 未就绪 → 设置按钮蓝色呼吸灯 + 发消息前置拦「请先配置」。每 30s 轮询(他人改了也同步)。
 */
export function useModelConfig() {
  return useQuery<ModelConfig>({
    queryKey: ['assistant', 'model-config'],
    queryFn: () => api<ModelConfig>('/assistant/model-config'),
    refetchInterval: 30_000,
    staleTime: 10_000,
  })
}

/** 保存模型接入配置(需 ai.configure;越权 → 后端 403)。保存即热加载生效。 */
export function saveModelConfig(body: ModelConfigUpdate): Promise<ModelConfig> {
  return api<ModelConfig>('/assistant/model-config', { method: 'PUT', body: JSON.stringify(body) })
}

/** 用「待保存的表单值」试调一次(不落盘),验证端点/协议/密钥/模型名是否可达可用。 */
export function testModelConfig(body: ModelConfigUpdate): Promise<ModelTestResult> {
  return api<ModelTestResult>('/assistant/model-config/test', j(body))
}

/** 清空某会话的多轮记忆(新建会话)。失败静默——前端已新建,后端旧记忆随会话自然失效。 */
export async function resetAssistant(sessionId: string): Promise<void> {
  try {
    await api('/assistant/reset', j({ session_id: sessionId }))
  } catch {
    /* 后端清理失败不影响前端新建会话 */
  }
}

/**
 * 流式真 Agent(SSE,POST /assistant/chat/stream)。逐帧回调:delta(逐字)/ step / ui /
 * proposal / done。fetch + ReadableStream 解析 `data: {json}\n\n`,边到边更新对话。
 *
 * `signal`(M25):调用方传 AbortController.signal 即可中止——fetch 连接与 reader.read()
 * 都会以 AbortError 拒绝,网络挂起也能被用户主动解除(否则 busy 永真锁死输入)。
 */
export async function sendChatStream(
  message: string,
  sessionId: string,
  onEvent: (ev: StreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch('/assistant/chat/stream', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, session_id: sessionId }),
    signal,
  })
  if (!res.ok || !res.body) {
    let detail = t('assistant.error.request_failed')
    try {
      detail = ((await res.json()) as { detail?: string })?.detail ?? detail
    } catch {
      /* 非 JSON 错误体,沿用默认 */
    }
    throw new Error(detail)
  }
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })
    let idx: number
    while ((idx = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, idx)
      buf = buf.slice(idx + 2)
      const line = frame.split('\n').find((l) => l.startsWith('data:'))
      if (!line) continue
      try {
        onEvent(JSON.parse(line.slice(5).trim()) as StreamEvent)
      } catch {
        /* 半截/坏帧,跳过 */
      }
    }
  }
}
