import { z } from 'zod'
import type { ResourceSpec } from '@/lib/backup'

/** 一张 KPI 卡的聚合数据(图标在前端按 key 映射,不入备份) */
export const overviewStatSchema = z.object({
  key: z.enum(['controlled', 'blocked', 'pending', 'audit']),
  label: z.string(),
  value: z.string(),
  unit: z.string().optional(),
  delta: z.string(),
  dir: z.enum(['up', 'down']),
  tone: z.enum(['accent', 'crit', 'high', 'ok']),
})

/** 总览页的聚合指标(平台侧统计,非逐事件;与逐事件的 events 资源互补) */
export const overviewSchema = z.object({
  stats: z.array(overviewStatSchema),
  attacks: z.object({
    total: z.string(),
    delta: z.string(),
    dir: z.enum(['up', 'down']),
    months: z.array(z.string()),
    monthly: z.array(z.number()),
    peakIndex: z.number(),
    // 当月按天序列(月视图);旧备份可缺省,缺省时月视图回退到年序列
    days: z.array(z.string()).optional(),
    daily: z.array(z.number()).optional(),
    dailyPeakIndex: z.number().optional(),
    monthTotal: z.string().optional(),
    monthDelta: z.string().optional(),
  }),
  protection: z.object({
    rate: z.number(),
    blocked: z.number(),
    target: z.number(),
  }),
})

/** 注册到备份系统的「总览指标」资源(单行) */
export const overviewResourceSpec: ResourceSpec = {
  kind: 'overview',
  label: '总览指标',
  schema: z.array(overviewSchema),
}

export type OverviewData = z.infer<typeof overviewSchema>
export type OverviewStat = z.infer<typeof overviewStatSchema>
