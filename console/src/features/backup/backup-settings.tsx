import { useState } from 'react'
import { AlertTriangle, Download, Trash2 } from 'lucide-react'
import { Badge, Button, Dialog, SettingRow, SettingSection, toast } from '@/components/ui'
import { useTranslation } from '@/lib/i18n'
import { getResourceSpecs, useBackup, BACKUP_SCHEMA_VERSION } from '@/lib/backup'
import { ImportBackupButtons } from './import-controls'

export function BackupSettings() {
  const { t } = useTranslation()
  const { resources, meta, hasData, exportBackup, clear } = useBackup()
  const specs = getResourceSpecs()
  const [confirmOpen, setConfirmOpen] = useState(false)

  // 已导入的资源条数总和(确认弹窗里如实告知将清空多少)
  const total = Object.values(resources).reduce((n, a) => n + a.length, 0)

  return (
    <div>
      <SettingSection title={t('backup.section.data')}>
        <SettingRow label={t('backup.row.import')} hint={t('backup.row.import_hint')}>
          <ImportBackupButtons size="sm" />
        </SettingRow>
        <SettingRow label={t('backup.row.export')}>
          <Button size="sm" onClick={exportBackup} disabled={!hasData}>
            <Download className="h-3.5 w-3.5" /> {t('backup.export.btn')}
          </Button>
        </SettingRow>
        <SettingRow label={t('backup.row.clear')}>
          <Button size="sm" variant="danger" disabled={!hasData} onClick={() => setConfirmOpen(true)}>
            <Trash2 className="h-3.5 w-3.5" /> {t('backup.clear.btn')}
          </Button>
        </SettingRow>
      </SettingSection>

      <Dialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-[18px] w-[18px] text-crit" strokeWidth={2} />
            {t('backup.clear.confirm_title')}
          </span>
        }
        description={t('backup.clear.confirm_desc')}
        widthClassName="max-w-md"
        footer={
          <>
            <Button size="sm" variant="ghost" onClick={() => setConfirmOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => {
                clear()
                setConfirmOpen(false)
                toast.success(t('backup.clear.done'))
              }}
            >
              <Trash2 className="h-3.5 w-3.5" /> {t('backup.clear.confirm_btn')}
            </Button>
          </>
        }
      >
        <p className="text-[14px] leading-relaxed text-ink-2">
          {t('backup.clear.warn', { n: total })}
        </p>
      </Dialog>

      <SettingSection title={t('backup.section.current')}>
        {hasData ? (
          <>
            {meta?.instance && (
              <SettingRow label={t('backup.row.instance')}>
                <span className="text-[15px] text-ink-2">{meta.instance}</span>
              </SettingRow>
            )}
            {meta?.exportedAt && (
              <SettingRow label={t('backup.row.exported_at')}>
                <span className="font-data text-[14px] text-ink-2">
                  {new Date(meta.exportedAt).toLocaleString('zh-CN')}
                </span>
              </SettingRow>
            )}
            <SettingRow label={t('backup.row.resources')}>
              <div className="flex flex-wrap justify-end gap-1.5">
                {specs.map((s) => {
                  const n = resources[s.kind]?.length ?? 0
                  return (
                    <Badge key={s.kind} tone={n > 0 ? 'accent' : 'neutral'}>
                      {s.label} {n}
                    </Badge>
                  )
                })}
              </div>
            </SettingRow>
          </>
        ) : (
          <div className="py-3.5 text-[14.5px] text-ink-3">{t('backup.empty')}</div>
        )}
      </SettingSection>

      <SettingSection title={t('backup.section.format')}>
        <SettingRow label={t('backup.row.filetype')}>
          <Badge tone="neutral">fulcrum.backup</Badge>
        </SettingRow>
        <SettingRow label={t('backup.row.schema')}>
          <span className="font-data text-[14px] text-ink-2">v{BACKUP_SCHEMA_VERSION}</span>
        </SettingRow>
        <SettingRow label={t('backup.row.supported')}>
          <div className="flex flex-wrap justify-end gap-1.5">
            {specs.map((s) => (
              <Badge key={s.kind} tone="neutral">
                {s.label}
              </Badge>
            ))}
          </div>
        </SettingRow>
      </SettingSection>
    </div>
  )
}
