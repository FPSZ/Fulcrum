import { z } from 'zod'
import type { ResourceSpec } from '@/lib/backup'

/** 风险事件的校验 schema(与 types.ts 的 SecurityEvent 对齐) */
export const eventSchema = z.object({
  id: z.string(),
  time: z.string(),
  sess: z.string(),
  srcType: z.enum(['文档', '网页', '用户', '知识库', '插件清单', '工具返回', '记忆']),
  trust: z.enum(['untrusted', 'semi', 'trusted']),
  risk: z.string(),
  tool: z.string(),
  policy: z.string(),
  level: z.enum(['critical', 'high', 'medium', 'low']),
  disp: z.enum(['block', 'approve', 'sanitize', 'allow']),
  verified: z.boolean(),
  excerpt: z.string(),
  intent: z.string(),
  args: z.string(),
  conf: z.number(),
  derived: z.string(),
  reason: z.string(),
})

/** 注册到备份系统的「风险事件」资源 */
export const eventResourceSpec: ResourceSpec = {
  kind: 'events',
  label: '风险事件',
  schema: z.array(eventSchema),
}
