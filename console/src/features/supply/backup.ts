import { z } from 'zod'
import type { ResourceSpec } from '@/lib/backup'

/** 供应链扫描报告的校验 schema(与 data.ts 的 ScanReport 对齐) */
export const scanReportSchema = z.object({
  component_id: z.string(),
  kind: z.string(),
  rating: z.enum(['block', 'approve', 'sanitize', 'allow']),
  risks: z.array(
    z.object({
      kind: z.string(),
      score: z.number(),
      severity: z.enum(['critical', 'high', 'medium', 'low']),
      detail: z.string(),
    }),
  ),
})

/** 注册到备份系统的「供应链扫描」资源 —— 演示数据经此载入,绝不前端硬编码自动注入。 */
export const scanResourceSpec: ResourceSpec = {
  kind: 'supply',
  label: '供应链扫描',
  schema: z.array(scanReportSchema),
}
