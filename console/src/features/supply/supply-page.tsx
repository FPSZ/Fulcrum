import { useState } from 'react'
import { Package, ShieldAlert } from 'lucide-react'
import { Badge, type BadgeTone, Card, EmptyState } from '@/components/ui'
import { useResource } from '@/lib/backup'
import { DISPOSITION_TONE as RATING_TONE } from '@/lib/disposition'
import { type MessageKey, useTranslation } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import { type Rating, type ScanReport, type Severity } from './data'
import { useSupplyScans } from './use-supply'

// 评级色调单一真源 @/lib/disposition(M29,Rating 与 Disposition 同值域);
// 文案按本页语境(「需复核」)留在 supply.rating.* 命名空间。
const RATING_KEY: Record<Rating, MessageKey> = {
  block: 'supply.rating.block',
  approve: 'supply.rating.approve',
  sanitize: 'supply.rating.sanitize',
  allow: 'supply.rating.allow',
}
const SEV_TONE: Record<Severity, BadgeTone> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'neutral',
}

export function SupplyPage() {
  const { t } = useTranslation()
  // 三态:真后端扫描评级 → 真;否则用户载入的备份演示数据;都没有 → 诚实空态(绝不自动塞假数据)。
  const live = useSupplyScans().data
  const backup = useResource<ScanReport>('supply')
  const reports = live && live.length > 0 ? live : backup
  const [selectedId, setSelectedId] = useState('')
  // 选中项不在当前列表(初始 / 真数据替换 seed 后)→ 回退首条
  const report = reports.find((r) => r.component_id === selectedId) ?? reports[0] ?? null
  const activeId = report?.component_id ?? ''

  if (reports.length === 0) {
    return (
      <EmptyState icon={Package} title={t('supply.empty.title')} hint={t('supply.empty.hint')} />
    )
  }

  return (
    <div className="flex min-h-0 flex-1">
      {/* 组件列表 */}
      <div className="w-[340px] shrink-0 space-y-2 overflow-y-auto border-r border-line p-3 max-[900px]:w-[280px]">
        {reports.map((r) => (
          <button
            key={r.component_id}
            type="button"
            onClick={() => setSelectedId(r.component_id)}
            className={cn(
              'focus-ring block w-full rounded-md border p-3 text-left transition-colors',
              r.component_id === activeId
                ? 'border-accent/40 bg-accent/5'
                : 'border-line bg-surface hover:border-line-3',
            )}
          >
            <div className="flex items-center gap-2">
              <code className="min-w-0 truncate text-[13px] font-medium text-ink">
                {r.component_id}
              </code>
              <Badge tone={RATING_TONE[r.rating]} dot className="ml-auto shrink-0">
                {t(RATING_KEY[r.rating])}
              </Badge>
            </div>
            <p className="mt-1.5 text-[12px] text-ink-3">
              {r.kind} · {t('supply.risk_count', { count: r.risks.length })}
            </p>
          </button>
        ))}
      </div>

      {/* 风险明细 */}
      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {report ? (
          <>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <h2 className="text-[15px] font-semibold text-ink">{report.component_id}</h2>
              <Badge tone={RATING_TONE[report.rating]}>
                <ShieldAlert className="h-3.5 w-3.5" />
                {t('supply.rating', { rating: t(RATING_KEY[report.rating]) })}
              </Badge>
              <span className="text-[13px] text-ink-3">
                {report.kind} · {t('supply.risk_count', { count: report.risks.length })}
              </span>
            </div>

            <Card className="mt-3 overflow-hidden">
              <table className="w-full text-[14px]">
                <thead>
                  <tr className="border-b border-line text-left text-[13px] text-ink-3">
                    <th className="px-4 py-2.5 font-medium">{t('supply.col.risk')}</th>
                    <th className="px-4 py-2.5 font-medium">{t('supply.col.severity')}</th>
                    <th className="px-4 py-2.5 font-medium">{t('supply.col.score')}</th>
                    <th className="px-4 py-2.5 font-medium">{t('supply.col.detail')}</th>
                  </tr>
                </thead>
                <tbody>
                  {report.risks.map((risk, i) => (
                    <tr key={`${risk.kind}-${i}`} className="border-b border-line/60 last:border-0">
                      <td className="px-4 py-2.5 font-mono text-[12.5px] text-ink-2">{risk.kind}</td>
                      <td className="px-4 py-2.5">
                        <Badge tone={SEV_TONE[risk.severity]}>{risk.severity}</Badge>
                      </td>
                      <td className="px-4 py-2.5 tabular-nums text-ink-3">{risk.score.toFixed(2)}</td>
                      <td className="px-4 py-2.5 text-[13px] text-ink-2">{risk.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          </>
        ) : null}
      </div>
    </div>
  )
}
