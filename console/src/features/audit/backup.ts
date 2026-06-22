import { z } from 'zod'
import type { ResourceSpec } from '@/lib/backup'

const disposition = z.enum(['block', 'approve', 'sanitize', 'allow'])

/** 审计会话链的校验 schema(与 data.ts 的 AuditSession 对齐) */
export const auditSessionSchema = z.object({
  session_id: z.string(),
  verified: z.boolean(),
  scenario: z.string(),
  events: z.array(
    z.object({
      index: z.number(),
      event_type: z.string(),
      subject_id: z.string().optional(),
      decision: disposition.optional(),
      reason: z.string().optional(),
      prev_hash: z.string(),
      event_hash: z.string(),
    }),
  ),
})

/** 注册到备份系统的「审计会话」资源 —— 演示数据经此载入,绝不前端硬编码自动注入。 */
export const auditResourceSpec: ResourceSpec = {
  kind: 'audit',
  label: '审计会话',
  schema: z.array(auditSessionSchema),
}
