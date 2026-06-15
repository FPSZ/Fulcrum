import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { buildBackup, parseBackup, type ImportReport } from './io'
import type { BackupMeta, ResourceData } from './types'

const LS_KEY = 'fulcrum.backup.v1'
/** 单文件导入上限:脱敏备份本就轻量(演示档约几十 KB),超过即视为误选大文件,
 *  直接拒绝,避免 file.text()+JSON.parse 把超大 JSON 读进内存卡死页面。 */
const MAX_BACKUP_BYTES = 5 * 1024 * 1024

interface PersistShape {
  resources: ResourceData
  meta: BackupMeta | null
}

function loadLS(): PersistShape | null {
  try {
    const raw = localStorage.getItem(LS_KEY)
    return raw ? (JSON.parse(raw) as PersistShape) : null
  } catch {
    return null
  }
}
function saveLS(v: PersistShape): void {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(v))
  } catch {
    /* 配额或隐私模式,忽略 */
  }
}
function stamp(): string {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`
}
function download(name: string, text: string): void {
  const blob = new Blob([text], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

interface BackupContextValue {
  resources: ResourceData
  meta: BackupMeta | null
  report: ImportReport | null
  hasData: boolean
  importText: (text: string) => ImportReport
  importFile: (file: File) => Promise<ImportReport>
  loadDemo: () => Promise<ImportReport>
  exportBackup: () => void
  clear: () => void
}

const Ctx = createContext<BackupContextValue | null>(null)

export function BackupProvider({ children }: { children: ReactNode }) {
  const init = loadLS()
  const [resources, setResources] = useState<ResourceData>(init?.resources ?? {})
  const [meta, setMeta] = useState<BackupMeta | null>(init?.meta ?? null)
  const [report, setReport] = useState<ImportReport | null>(null)

  const importText = useCallback((text: string) => {
    const { data, report } = parseBackup(text)
    setReport(report)
    if (report.ok) {
      setResources(data)
      setMeta(report.meta ?? null)
      saveLS({ resources: data, meta: report.meta ?? null })
    }
    return report
  }, [])

  const importFile = useCallback(
    async (file: File) => {
      if (file.size > MAX_BACKUP_BYTES) {
        const mb = (MAX_BACKUP_BYTES / 1024 / 1024).toFixed(0)
        const r: ImportReport = {
          ok: false,
          imported: [],
          skipped: [],
          error: `文件过大(${(file.size / 1024 / 1024).toFixed(1)} MB),备份不应超过 ${mb} MB,请确认选对了文件`,
        }
        setReport(r)
        return r
      }
      return importText(await file.text())
    },
    [importText],
  )

  const loadDemo = useCallback(async () => {
    const res = await fetch(`${import.meta.env.BASE_URL}demo-backup.json`)
    if (!res.ok) {
      const r: ImportReport = { ok: false, imported: [], skipped: [], error: '未找到演示备份文件' }
      setReport(r)
      return r
    }
    return importText(await res.text())
  }, [importText])

  const exportBackup = useCallback(() => {
    const file = buildBackup(resources, {
      instance: meta?.instance ?? '枢衡控制台',
      note: '控制台手动导出',
    })
    download(`fulcrum-backup-${stamp()}.json`, JSON.stringify(file, null, 2))
  }, [resources, meta])

  const clear = useCallback(() => {
    setResources({})
    setMeta(null)
    setReport(null)
    localStorage.removeItem(LS_KEY)
  }, [])

  const hasData = Object.values(resources).some((a) => a.length > 0)

  return (
    <Ctx.Provider
      value={{ resources, meta, report, hasData, importText, importFile, loadDemo, exportBackup, clear }}
    >
      {children}
    </Ctx.Provider>
  )
}

export function useBackup(): BackupContextValue {
  const c = useContext(Ctx)
  if (!c) throw new Error('useBackup 必须在 <BackupProvider> 内使用')
  return c
}

const EMPTY: readonly never[] = []

/** 读取某类资源(带类型)。未导入时返回稳定的空数组(引用不变,避免触发副作用循环)。 */
export function useResource<T>(kind: string): T[] {
  const { resources } = useBackup()
  return (resources[kind] as T[] | undefined) ?? (EMPTY as unknown as T[])
}
