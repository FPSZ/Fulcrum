import { z } from 'zod'
import type { ResourceSpec } from '@/lib/backup'

/** 工具调用治理流水的校验 schema(与 data.ts 的 ToolCall 对齐) */
export const toolCallSchema = z.object({
  id: z.string(),
  time: z.string(),
  tool: z.string(),
  args: z.string(),
  source_trust: z.enum(['untrusted', 'semi', 'trusted']),
  risk_score: z.number(),
  risk_level: z.enum(['critical', 'high', 'medium', 'low']),
  attribution_confidence: z.number(),
  decision: z.enum(['block', 'approve', 'sanitize', 'allow']),
  rule: z.string().nullable(),
  executed: z.boolean(),
  reason: z.string(),
})

/** 注册到备份系统的「工具调用」资源 —— 演示数据经此载入,绝不前端硬编码自动注入。 */
export const toolCallResourceSpec: ResourceSpec = {
  kind: 'tools',
  label: '工具调用',
  schema: z.array(toolCallSchema),
}
