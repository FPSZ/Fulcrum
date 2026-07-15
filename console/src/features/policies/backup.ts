import { z } from 'zod'
import type { ResourceSpec } from '@/lib/backup'

const dispositionSchema = z.enum(['block', 'approve', 'sanitize', 'allow'])

/** 当前策略集的离线快照 schema，与 GET /policies 的 PolicySet 保持同构。 */
export const policySetSchema = z.object({
  name: z.string(),
  version: z.number().int().positive(),
  default: dispositionSchema,
  workspace: z.string(),
  allow_domains: z.array(z.string()),
  rules: z.array(
    z.object({
      id: z.string(),
      when: z.array(z.object({ key: z.string(), value: z.string() })),
      decision: dispositionSchema,
      risk_level: z.enum(['critical', 'high', 'medium', 'low']),
      reason: z.string(),
    }),
  ),
})

/** 注册到备份系统的「策略」资源，仅供离线预览，不会写回运行策略。 */
export const policyResourceSpec: ResourceSpec = {
  kind: 'policies',
  label: '策略',
  schema: z.array(policySetSchema),
}
