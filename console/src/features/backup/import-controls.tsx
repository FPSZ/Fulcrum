import { useRef } from 'react'
import { Sparkles, Upload } from 'lucide-react'
import { Button, toast } from '@/components/ui'
import { t, useTranslation } from '@/lib/i18n'
import { useBackup, type ImportReport } from '@/lib/backup'

export function notifyImport(r: ImportReport): void {
  if (!r.ok) {
    toast.error(t('backup.import.failed'), { description: r.error })
    return
  }
  const total = r.imported.reduce((s, i) => s + i.count, 0)
  if (total === 0) {
    toast.error(t('backup.import.none'), {
      description: r.skipped.length ? t('backup.import.none_skipped', { n: r.skipped.length }) : undefined,
    })
    return
  }
  const parts = r.imported.map((i) => `${i.label} ${i.count}`).join(' · ')
  toast.success(t('backup.import.ok'), {
    description: r.skipped.length
      ? t('backup.import.ok_skipped', { parts, n: r.skipped.length })
      : t('backup.import.ok_desc', { parts }),
  })
}

export function ImportBackupButtons({ size = 'md' }: { size?: 'sm' | 'md' }) {
  const { t } = useTranslation()
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
        <Upload className="h-3.5 w-3.5" /> {t('backup.import.btn')}
      </Button>
      <Button size={size} onClick={async () => notifyImport(await loadDemo())}>
        <Sparkles className="h-3.5 w-3.5" /> {t('backup.demo.btn')}
      </Button>
    </div>
  )
}
