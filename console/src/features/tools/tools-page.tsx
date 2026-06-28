import { useMemo, useState } from 'react'
import { Plug } from 'lucide-react'
import { Badge, type BadgeTone, Card, EmptyState, Segmented } from '@/components/ui'
import { useResource } from '@/lib/backup'
import { type MessageKey, useTranslation } from '@/lib/i18n'
import { type Disposition, type ToolCall, type Trust } from './data'
import { useToolCalls } from './use-tools'

const DISP_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const DISP_KEY: Record<Disposition, MessageKey> = {
  block: 'tools.disp.block',
  approve: 'tools.disp.approve',
  sanitize: 'tools.disp.sanitize',
  allow: 'tools.disp.allow',
}
const TRUST_KEY: Record<Trust, MessageKey> = {
  untrusted: 'tools.trust.untrusted',
  semi: 'tools.trust.semi',
  trusted: 'tools.trust.trusted',
}
const TRUST_TONE: Record<Trust, BadgeTone> = { untrusted: 'crit', semi: 'med', trusted: 'ok' }

type Filter = 'all' | 'held' | 'allow'

export function ToolsPage() {
  const { t } = useTranslation()
  const FILTERS: { value: Filter; label: string }[] = [
    { value: 'all', label: t('tools.filter.all') },
    { value: 'held', label: t('tools.filter.held') },
    { value: 'allow', label: t('tools.filter.allow') },
  ]
  const [filter, setFilter] = useState<Filter>('all')
  // 三态:真后端工具流水 → 真;否则用户载入的备份演示数据;都没有 → 诚实空态(绝不自动塞假数据)。
  const live = useToolCalls().data
  const backup = useResource<ToolCall>('tools')
  const calls = live && live.length > 0 ? live : backup
  const rows = useMemo(
    () =>
      calls.filter((c) =>
        filter === 'all' ? true : filter === 'allow' ? c.decision === 'allow' : c.decision !== 'allow',
      ),
    [filter, calls],
  )
  const held = calls.filter((c) => c.decision !== 'allow').length

  if (calls.length === 0) {
    return (
      <EmptyState icon={Plug} title={t('tools.empty.title')} hint={t('tools.empty.hint')} />
    )
  }

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-ink-3">
        <span>{t('tools.summary', { total: calls.length, held })}</span>
      </div>

      <div className="flex items-center gap-3">
        <Segmented value={filter} onValueChange={(v) => setFilter(v as Filter)} items={FILTERS} />
      </div>

      <Card className="overflow-hidden">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-line text-left text-[13px] text-ink-3">
              <th className="px-4 py-2.5 font-medium">{t('tools.col.time')}</th>
              <th className="px-4 py-2.5 font-medium">{t('tools.col.tool')}</th>
              <th className="px-4 py-2.5 font-medium">{t('tools.col.source')}</th>
              <th className="px-4 py-2.5 font-medium">{t('tools.col.risk')}</th>
              <th className="px-4 py-2.5 font-medium">{t('tools.col.attribution')}</th>
              <th className="px-4 py-2.5 font-medium">{t('tools.col.disposition')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id} className="border-b border-line/60 align-top last:border-0">
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-[12.5px] text-ink-3">
                  {c.time}
                </td>
                <td className="px-4 py-2.5">
                  <div className="font-medium text-ink">{c.tool}</div>
                  <div className="mt-0.5 max-w-[320px] truncate font-mono text-[12px] text-ink-3">
                    {c.args}
                  </div>
                </td>
                <td className="px-4 py-2.5">
                  <Badge tone={TRUST_TONE[c.source_trust]}>{t(TRUST_KEY[c.source_trust])}</Badge>
                </td>
                <td className="px-4 py-2.5">
                  <Badge tone={DISP_TONE[c.decision] === 'ok' ? 'ok' : c.risk_level === 'critical' ? 'crit' : c.risk_level === 'high' ? 'high' : 'med'}>
                    {c.risk_score.toFixed(2)}
                  </Badge>
                </td>
                <td className="px-4 py-2.5 tabular-nums text-[13px] text-ink-3">
                  {(c.attribution_confidence * 100).toFixed(0)}%
                </td>
                <td className="px-4 py-2.5">
                  <Badge tone={DISP_TONE[c.decision]} dot>
                    {t(DISP_KEY[c.decision])}
                  </Badge>
                  <div className="mt-1 max-w-[280px] text-[12.5px] leading-snug text-ink-3">
                    {c.rule && <code className="text-ink-2">{c.rule}</code>}
                    {c.rule && ' · '}
                    {c.reason}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
