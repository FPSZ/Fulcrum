import { z } from 'zod'
import { getResourceSpec } from './registry'
import type { BackupFile, BackupMeta, ResourceData } from './types'

export const BACKUP_SCHEMA_VERSION = 1

export interface ImportReport {
  ok: boolean
  meta?: BackupMeta
  imported: { kind: string; label: string; count: number }[]
  skipped: { kind: string; reason: string }[]
  error?: string
}

const envelopeSchema = z.object({
  kind: z.literal('fulcrum.backup'),
  schemaVersion: z.number(),
  meta: z
    .object({
      exportedAt: z.string().optional(),
      instance: z.string().optional(),
      note: z.string().optional(),
      appVersion: z.string().optional(),
    })
    .optional(),
  resources: z.record(z.string(), z.array(z.unknown())),
})

function fail(error: string): { data: ResourceData; report: ImportReport } {
  return { data: {}, report: { ok: false, imported: [], skipped: [], error } }
}

/** 解析一段备份 JSON 文本 → 校验 → 分发到已注册的资源导入器 */
export function parseBackup(text: string): { data: ResourceData; report: ImportReport } {
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    return fail('文件不是合法的 JSON')
  }

  const parsed = envelopeSchema.safeParse(json)
  if (!parsed.success) {
    return fail('不是有效的枢衡备份文件(应含 kind: "fulcrum.backup" 与 resources)')
  }
  const file = parsed.data

  const data: ResourceData = {}
  const imported: ImportReport['imported'] = []
  const skipped: ImportReport['skipped'] = []

  for (const [kind, arr] of Object.entries(file.resources)) {
    const spec = getResourceSpec(kind)
    if (!spec) {
      skipped.push({ kind, reason: '未知资源类型(当前版本不支持,已忽略)' })
      continue
    }
    const res = spec.schema.safeParse(arr)
    if (!res.success) {
      skipped.push({ kind, reason: `${spec.label} 数据校验失败` })
      continue
    }
    data[kind] = res.data as unknown[]
    imported.push({ kind, label: spec.label, count: (res.data as unknown[]).length })
  }

  return { data, report: { ok: true, meta: file.meta, imported, skipped } }
}

/** 用当前资源数据构造一个备份文件对象 */
export function buildBackup(resources: ResourceData, meta: BackupMeta = {}): BackupFile {
  return {
    kind: 'fulcrum.backup',
    schemaVersion: BACKUP_SCHEMA_VERSION,
    meta: { exportedAt: new Date().toISOString(), ...meta },
    resources,
  }
}
