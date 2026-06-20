import { useQuery } from '@tanstack/react-query'
import { api, j } from '@/lib/api/client'
import type { AssistantAction, PlanResult } from './data'

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
