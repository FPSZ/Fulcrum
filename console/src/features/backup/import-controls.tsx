import { useRef } from 'react'
import { Sparkles, Upload } from 'lucide-react'
import { Button, toast } from '@/components/ui'
import { useBackup, type ImportReport } from '@/lib/backup'

export function notifyImport(r: ImportReport): void {
  if (!r.ok) {
    toast.error('导入失败', { description: r.error })
    return
  }
  const total = r.imported.reduce((s, i) => s + i.count, 0)
  if (total === 0) {
    toast.error('未导入任何已知资源', {
      description: r.skipped.length ? `忽略了 ${r.skipped.length} 类未知资源` : undefined,
    })
    return
  }
  const parts = r.imported.map((i) => `${i.label} ${i.count}`).join(' · ')
  toast.success('导入成功', {
    description: `${parts}${r.skipped.length ? ` · 跳过 ${r.skipped.length} 类未知资源` : ''}`,
  })
}

export function ImportBackupButtons({ size = 'md' }: { size?: 'sm' | 'md' }) {
  const { importFile, loadDemo } = useBackup()
  const ref = useRef<HTMLInputElement>(null)
  return (
    <div className="flex items-center gap-2">
      <input
        ref={ref}
        type="file"
        accept="application/json,.json"
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0]
          e.currentTarget.value = ''
          if (f) notifyImport(await importFile(f))
        }}
      />
      <Button variant="primary" size={size} onClick={() => ref.current?.click()}>
        <Upload className="h-3.5 w-3.5" /> 导入备份
      </Button>
      <Button size={size} onClick={async () => notifyImport(await loadDemo())}>
        <Sparkles className="h-3.5 w-3.5" /> 载入演示备份
      </Button>
    </div>
  )
}
