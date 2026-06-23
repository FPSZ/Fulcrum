import { useState } from 'react'
import { AlertTriangle, Download, Trash2 } from 'lucide-react'
import { Badge, Button, Dialog, SettingRow, SettingSection, toast } from '@/components/ui'
import { getResourceSpecs, useBackup, BACKUP_SCHEMA_VERSION } from '@/lib/backup'
import { ImportBackupButtons } from './import-controls'

export function BackupSettings() {
  const { resources, meta, hasData, exportBackup, clear } = useBackup()
  const specs = getResourceSpecs()
  const [confirmOpen, setConfirmOpen] = useState(false)

  // 已导入的资源条数总和(确认弹窗里如实告知将清空多少)
  const total = Object.values(resources).reduce((n, a) => n + a.length, 0)

  return (
    <div>
      <SettingSection
        title="数据与备份"
        desc="私有化部署:所有数据仅存于本地实例,不出域。通过备份文件导入 / 导出迁移数据。"
      >
        <SettingRow label="导入备份" hint="选择枢衡备份文件(.json),或载入内置演示备份">
          <ImportBackupButtons size="sm" />
        </SettingRow>
        <SettingRow label="导出当前数据" hint="把当前实例的数据打包为备份文件下载">
          <Button size="sm" onClick={exportBackup} disabled={!hasData}>
            <Download className="h-3.5 w-3.5" /> 导出备份
          </Button>
        </SettingRow>
        <SettingRow label="清空本地数据" hint="移除本机已导入的数据(不影响备份文件本身)">
          <Button size="sm" variant="danger" disabled={!hasData} onClick={() => setConfirmOpen(true)}>
            <Trash2 className="h-3.5 w-3.5" /> 清空
          </Button>
        </SettingRow>
      </SettingSection>

      <Dialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-[18px] w-[18px] text-crit" strokeWidth={2} />
            清空本地数据?
          </span>
        }
        description="此操作不可撤销。"
        widthClassName="max-w-md"
        footer={
          <>
            <Button size="sm" variant="ghost" onClick={() => setConfirmOpen(false)}>
              取消
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => {
                clear()
                setConfirmOpen(false)
                toast.success('已清空本地数据')
              }}
            >
              <Trash2 className="h-3.5 w-3.5" /> 确认清空
            </Button>
          </>
        }
      >
        <p className="text-[14px] leading-relaxed text-ink-2">
          将移除本机已导入的 <b className="font-semibold text-ink">{total}</b> 条数据,各页面随即回到空态。
          备份文件本身不受影响,可重新导入或载入演示备份恢复。
        </p>
      </Dialog>

      <SettingSection title="当前备份" desc="本机已导入的资源概览。">
        {hasData ? (
          <>
            {meta?.instance && (
              <SettingRow label="来源实例">
                <span className="text-[15px] text-ink-2">{meta.instance}</span>
              </SettingRow>
            )}
            {meta?.exportedAt && (
              <SettingRow label="导出时间">
                <span className="font-data text-[14px] text-ink-2">
                  {new Date(meta.exportedAt).toLocaleString('zh-CN')}
                </span>
              </SettingRow>
            )}
            <SettingRow label="资源" hint="备份按资源类型分桶,后续可扩展更多类型">
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
          <div className="py-3.5 text-[14.5px] text-ink-3">尚未导入任何数据。</div>
        )}
      </SettingSection>

      <SettingSection
        title="备份格式"
        desc="版本化、按资源类型分桶的容器,支持向前兼容(未知资源类型会被安全忽略)。"
      >
        <SettingRow label="文件类型">
          <Badge tone="neutral">fulcrum.backup</Badge>
        </SettingRow>
        <SettingRow label="Schema 版本">
          <span className="font-data text-[14px] text-ink-2">v{BACKUP_SCHEMA_VERSION}</span>
        </SettingRow>
        <SettingRow label="当前支持资源" hint="路线图:策略 / 工具 / 供应链 / 审计链 / 评测 …(逐步开放导入)">
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
