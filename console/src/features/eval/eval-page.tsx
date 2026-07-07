import { useMemo, useState } from 'react'
import { Check, FlaskConical, X } from 'lucide-react'
import { Badge, Card, EmptyState, Segmented } from '@/components/ui'
import { dispositionTone } from '@/lib/disposition'
import { cn } from '@/lib/utils'
import { type MessageKey, useTranslation } from '@/lib/i18n'
import { METRIC_ROWS } from './data'
import { useEvalReport } from './use-eval'

const pct = (v: number) => `${(v * 100).toFixed(1)}%`

// 色调单一真源 @/lib/disposition(M29);样例处置来自报告 JSON(未收窄字符串),
// 走宽入口 dispositionTone(未知值回退 neutral,口径同旧 `?? 'neutral'`)。
// 处置标签 key(在调用时经 t() 解析当前语言)。
const DISP_KEY: Record<string, MessageKey> = {
  block: 'eval.disp.block',
  approve: 'eval.disp.approve',
  sanitize: 'eval.disp.sanitize',
  allow: 'eval.disp.allow',
}

type Filter = 'all' | 'malicious' | 'benign'

export function EvalPage() {
  // 评测是离线产物(python -m fulcrum.eval → /eval/report)。无报告/不可达 → 诚实空态(绝不塞假指标)。
  const { t } = useTranslation()
  const report = useEvalReport().data
  const [filter, setFilter] = useState<Filter>('all')
  const FILTERS: { value: Filter; label: string }[] = [
    { value: 'all', label: t('eval.filter.all') },
    { value: 'malicious', label: t('eval.filter.malicious') },
    { value: 'benign', label: t('eval.filter.benign') },
  ]
  const dispLabel = (d: string) => (DISP_KEY[d] ? t(DISP_KEY[d]) : d)
  const rows = useMemo(
    () =>
      (report?.samples ?? []).filter((s) =>
        filter === 'all' ? true : filter === 'malicious' ? s.malicious : !s.malicious,
      ),
    [filter, report],
  )

  if (!report) {
    return <EmptyState icon={FlaskConical} title={t('eval.empty.title')} hint={t('eval.empty.hint')} />
  }
  const { dataset, metrics } = report
  const tot = metrics.totals

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
      {/* 概要 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 className="text-[15px] font-semibold text-ink">{t('eval.main.title')}</h2>
        <span className="text-[13px] text-ink-3">
          {t('eval.summary', {
            dataset,
            samples: tot.samples,
            malicious: tot.malicious,
            benign: tot.benign,
            tp: tot.tp,
            fn: tot.fn,
            fp: tot.fp,
            tn: tot.tn,
          })}
        </span>
      </div>

      {/* 主结果表 */}
      <Card className="overflow-hidden">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-line text-left text-[13px] text-ink-3">
              <th className="px-4 py-2.5 font-medium">{t('eval.col.metric')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.baseline')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.fulcrum')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.target')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.pass')}</th>
            </tr>
          </thead>
          <tbody>
            {METRIC_ROWS.map((r) => {
              const v = metrics[r.key]
              const ok = r.pass(v)
              return (
                <tr key={r.key} className="border-b border-line/60 last:border-0">
                  <td className="px-4 py-2.5 text-ink-2">{t(r.labelKey)}</td>
                  <td className="px-4 py-2.5 tabular-nums text-ink-3">{r.baseline}</td>
                  <td className="px-4 py-2.5 font-semibold tabular-nums text-ink">{pct(v)}</td>
                  <td className="px-4 py-2.5 tabular-nums text-ink-3">{r.target}</td>
                  <td className="px-4 py-2.5">
                    <Badge tone={ok ? 'ok' : 'high'}>
                      {ok ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                      {ok ? t('eval.pass') : t('eval.fail')}
                    </Badge>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </Card>
      <p className="text-[12.5px] text-ink-3">{t('eval.footnote')}</p>

      {/* 逐样例明细 */}
      <div className="flex items-center gap-3 pt-1">
        <h3 className="text-[15px] font-semibold text-ink">{t('eval.samples.title')}</h3>
        <Segmented value={filter} onValueChange={(v) => setFilter(v as Filter)} items={FILTERS} />
      </div>
      <Card className="overflow-hidden">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-line text-left text-[13px] text-ink-3">
              <th className="px-4 py-2.5 font-medium">{t('eval.col.sample')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.attack_type')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.nature')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.expected')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.predicted')}</th>
              <th className="px-4 py-2.5 font-medium">{t('eval.col.verdict')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.sample_id} className="border-b border-line/60 last:border-0">
                <td className="px-4 py-2.5 font-mono text-[13px] text-ink-2">{s.sample_id}</td>
                <td className="px-4 py-2.5 text-ink-3">{s.attack_type}</td>
                <td className="px-4 py-2.5">
                  <Badge tone={s.malicious ? 'crit' : 'ok'}>
                    {s.malicious ? t('eval.nature.malicious') : t('eval.nature.benign')}
                  </Badge>
                </td>
                <td className="px-4 py-2.5">
                  <Badge tone={dispositionTone(s.expected)}>{dispLabel(s.expected)}</Badge>
                </td>
                <td className="px-4 py-2.5">
                  <Badge tone={dispositionTone(s.predicted)}>{dispLabel(s.predicted)}</Badge>
                </td>
                <td className="px-4 py-2.5">
                  <span
                    className={cn(
                      'inline-flex items-center gap-1 text-[13px]',
                      s.decision_correct ? 'text-ok' : 'text-high',
                    )}
                  >
                    {s.decision_correct ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
                    {s.decision_correct ? t('eval.verdict.correct') : t('eval.verdict.deviation')}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
