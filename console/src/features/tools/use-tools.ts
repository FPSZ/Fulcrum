import { useQuery } from '@tanstack/react-query'
import { api, j } from '@/lib/api/client'
import type { Disposition, RiskLevel, ToolCall, Trust } from './data'

/** 后端 ToolCallDTO 的镜像(枚举为后端原值,时间为 epoch 秒)。 */
interface ToolCallDTO {
  id: string
  time: number
  sess: string
  tool: string
  args: string
  source_trust: string | null
  risk_score: number
  risk_level: string
  attribution_confidence: number
  decision: string
  rule: string | null
  executed: boolean
  reason: string
}

const TRUST_MAP: Record<string, Trust> = {
  untrusted: 'untrusted',
  semi_trusted: 'semi',
  trusted: 'trusted',
}
const LEVELS = new Set(['critical', 'high', 'medium', 'low'])
const DISPS = new Set(['block', 'approve', 'sanitize', 'allow'])

const fmtTime = (epochSec: number) =>
  new Date(epochSec * 1000).toLocaleTimeString('zh-CN', { hour12: false })

function toToolCall(d: ToolCallDTO): ToolCall {
  return {
    id: d.id,
    time: fmtTime(d.time),
    tool: d.tool,
    args: d.args,
    // 无可核验来源(如内部直接调用)→ 视作可信上下文展示
    source_trust: (d.source_trust && TRUST_MAP[d.source_trust]) || 'trusted',
    risk_score: d.risk_score,
    risk_level: (LEVELS.has(d.risk_level) ? d.risk_level : 'low') as RiskLevel,
    attribution_confidence: d.attribution_confidence,
    decision: (DISPS.has(d.decision) ? d.decision : 'allow') as Disposition,
    rule: d.rule,
    executed: d.executed,
    reason: d.reason,
  }
}

/**
 * 工具调用治理流水(接真后端 GET /tools/calls)。每 15s 轮询。
 * 工具调用穿过枢衡(模型编排 / 直接工具调用)才有数据;无权限/不可达/空 → 回退演示 seed。
 */
export function useToolCalls() {
  return useQuery<ToolCall[]>({
    queryKey: ['tools', 'calls'],
    queryFn: async () => (await api<ToolCallDTO[]>('/tools/calls')).map(toToolCall),
    refetchInterval: 15_000,
  })
}

export interface ToolCallProposal {
  tool: string
  label: string
  risk: string
  args: Record<string, unknown>
  requires: string[]
  note: string
  action_token: string
}

interface ConfirmResponse {
  ok: boolean
  summary: string
  error: string | null
}

export function proposeToolCall(
  toolName: string,
  toolArguments: Record<string, unknown>,
  sessionId: string,
): Promise<ToolCallProposal> {
  return api<ToolCallProposal>(
    '/tools/call/proposal',
    j({ tool_name: toolName, arguments: toolArguments, session_id: sessionId }),
  )
}

export function confirmToolCall(
  actionToken: string,
  args: Record<string, unknown>,
  sessionId: string,
): Promise<ConfirmResponse> {
  return api<ConfirmResponse>(
    '/assistant/confirm',
    j({ action_token: actionToken, edited_args: args, session_id: sessionId }),
  )
}
