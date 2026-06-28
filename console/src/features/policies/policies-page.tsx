import { useMemo, useState } from 'react'
import { ArrowRight, Scale } from 'lucide-react'
import { Badge, type BadgeTone, Card, EmptyState, Segmented } from '@/components/ui'
import { type MessageKey, useTranslation } from '@/lib/i18n'
import { type Disposition } from './data'
import { usePolicies } from './use-policies'

const DISP_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const DISP_KEY: Record<Disposition, MessageKey> = {
  block: 'policies.disp.block',
  approve: 'policies.disp.approve',
  sanitize: 'policies.disp.sanitize',
  allow: 'policies.disp.allow',
}
const LEVEL_TONE: Record<string, BadgeTone> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'neutral',
}

type Filter = 'all' | Disposition

export function PoliciesPage() {
  const { t } = useTranslation()
  const FILTERS: { value: Filter; label: string }[] = [
    { value: 'all', label: t('policies.filter.all') },
    { value: 'block', label: t('policies.filter.block') },
    { value: 'approve', label: t('policies.filter.approve') },
  ]
  // 策略是后端装配的配置事实(/policies),后端在跑即非空;不可达/非 yaml 引擎 → 诚实空态(不塞假数据)。
  const ps = usePolicies().data
  const [filter, setFilter] = useState<Filter>('all')
  const rules = useMemo(
    () => (ps ? ps.rules.filter((r) => filter === 'all' || r.decision === filter) : []),
    [filter, ps],
  )

  if (!ps) {
    return (
      <EmptyState icon={Scale} title={t('policies.empty.title')} hint={t('policies.empty.hint')} />
    )
  }

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
      {/* 当前装配策略的配置事实(标题已在顶栏,这里只给状态) */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-ink-3">
        <span>
          {t('policies.default')} <Badge tone={DISP_TONE[ps.default]}>{t(DISP_KEY[ps.default])}</Badge>
        </span>
        <span>
          {t('policies.workspace')} <code className="text-ink-2">{ps.workspace}</code>
        </span>
        <span>
          {t('policies.allow_domains')} {ps.allow_domains.join('、')}
        </span>
        <span>{t('policies.version', { version: ps.version })}</span>
      </div>

      <div className="flex items-center gap-3">
        <span className="text-[13px] text-ink-3">{t('policies.rule_count', { count: rules.length })}</span>
        <Segmented value={filter} onValueChange={(v) => setFilter(v as Filter)} items={FILTERS} />
      </div>

      {/* 规则列表 */}
      <div className="space-y-2.5">
        {rules.map((r, i) => (
          <Card key={r.id} className="p-3.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="flex h-5 w-5 items-center justify-center rounded-xs bg-surface-2 text-[12px] tabular-nums text-ink-3">
                {i + 1}
              </span>
              <code className="text-[13.5px] font-medium text-ink">{r.id}</code>
              <Badge tone={LEVEL_TONE[r.risk_level] ?? 'neutral'}>{r.risk_level}</Badge>
              <span className="ml-auto inline-flex items-center gap-1.5 text-[13px] text-ink-3">
                {t('policies.condition_hit')} <ArrowRight className="h-3.5 w-3.5" />
                <Badge tone={DISP_TONE[r.decision]} dot>
                  {t(DISP_KEY[r.decision])}
                </Badge>
              </span>
            </div>
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
              {r.when.map((c) => (
                <span
                  key={c.key}
                  className="inline-flex items-center gap-1 rounded-xs border border-line-2 bg-surface px-2 py-0.5 text-[12.5px] text-ink-2"
                >
                  <span className="text-ink-3">{c.key}</span>
                  <span className="text-line-3">=</span>
                  <span className="font-medium">{c.value}</span>
                </span>
              ))}
            </div>
            <p className="mt-2 text-[13px] leading-relaxed text-ink-2">{r.reason}</p>
          </Card>
        ))}
      </div>
    </div>
  )
}
