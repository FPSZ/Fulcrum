import { useMemo, useState } from 'react'
import { ArrowRight, Scale } from 'lucide-react'
import { Badge, type BadgeTone, Card, Segmented } from '@/components/ui'
import { POLICY_SET, type Disposition } from './data'

const DISP_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const DISP_LABEL: Record<Disposition, string> = {
  block: '阻断',
  approve: '审批',
  sanitize: '净化',
  allow: '放行',
}
const LEVEL_TONE: Record<string, BadgeTone> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'neutral',
}

type Filter = 'all' | Disposition
const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'block', label: '阻断' },
  { value: 'approve', label: '审批' },
]

export function PoliciesPage() {
  const ps = POLICY_SET
  const [filter, setFilter] = useState<Filter>('all')
  const rules = useMemo(
    () => ps.rules.filter((r) => filter === 'all' || r.decision === filter),
    [filter, ps.rules],
  )

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
      {/* 策略集元信息 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 className="text-[15px] font-semibold text-ink">{ps.name}</h2>
        <span className="text-[13px] text-ink-3">
          v{ps.version} · 默认处置{' '}
          <Badge tone={DISP_TONE[ps.default]}>{DISP_LABEL[ps.default]}</Badge> · 工作区{' '}
          <code className="text-ink-2">{ps.workspace}</code> · 外联白名单 {ps.allow_domains.join('、')}
        </span>
      </div>
      <p className="text-[12.5px] text-ink-3">
        声明式规则,自上而下首条命中即决定;均未命中按默认处置。改策略只改{' '}
        <code className="text-ink-2">data/policies/*.yml</code>,核心代码零改动。
      </p>

      <div className="flex items-center gap-3">
        <span className="text-[13px] text-ink-3">{rules.length} 条规则</span>
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
                条件命中 <ArrowRight className="h-3.5 w-3.5" />
                <Badge tone={DISP_TONE[r.decision]} dot>
                  {DISP_LABEL[r.decision]}
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

      <div className="flex items-center gap-2 pb-2 text-[12.5px] text-ink-3">
        <Scale className="h-3.5 w-3.5" />
        策略引擎:`YamlPolicyEngine`(条件 → 分级处置 allow / sanitize / approve / block)
      </div>
    </div>
  )
}
