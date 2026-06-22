import { useMemo, useState } from 'react'
import { Check, FlaskConical, X } from 'lucide-react'
import { Badge, type BadgeTone, Card, EmptyState, Segmented } from '@/components/ui'
import { cn } from '@/lib/utils'
import { METRIC_ROWS } from './data'
import { useEvalReport } from './use-eval'

const pct = (v: number) => `${(v * 100).toFixed(1)}%`

const DISP_TONE: Record<string, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const DISP_LABEL: Record<string, string> = {
  block: '阻断',
  approve: '审批',
  sanitize: '净化',
  allow: '放行',
}

type Filter = 'all' | 'malicious' | 'benign'
const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'malicious', label: '攻击' },
  { value: 'benign', label: '正常' },
]

export function EvalPage() {
  // 评测是离线产物(python -m fulcrum.eval → /eval/report)。无报告/不可达 → 诚实空态(绝不塞假指标)。
  const report = useEvalReport().data
  const [filter, setFilter] = useState<Filter>('all')
  const rows = useMemo(
    () =>
      (report?.samples ?? []).filter((s) =>
        filter === 'all' ? true : filter === 'malicious' ? s.malicious : !s.malicious,
      ),
    [filter, report],
  )

  if (!report) {
    return (
      <EmptyState
        icon={FlaskConical}
        title="暂无评测报告"
        hint="运行 uv run python -m fulcrum.eval --dataset samples/eval/corpus 生成报告后,这里显示 P0 主结果表与逐样例。"
      />
    )
  }
  const { dataset, metrics } = report
  const t = metrics.totals

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
      {/* 概要 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 className="text-[15px] font-semibold text-ink">P0 主结果表</h2>
        <span className="text-[13px] text-ink-3">
          数据集 <code className="text-ink-2">{dataset}</code> · {t.samples} 条(攻击 {t.malicious}{' '}
          · 正常 {t.benign})· 混淆 TP {t.tp}/FN {t.fn}/FP {t.fp}/TN {t.tn}
        </span>
      </div>

      {/* 主结果表 */}
      <Card className="overflow-hidden">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-line text-left text-[13px] text-ink-3">
              <th className="px-4 py-2.5 font-medium">指标</th>
              <th className="px-4 py-2.5 font-medium">Baseline</th>
              <th className="px-4 py-2.5 font-medium">Fulcrum</th>
              <th className="px-4 py-2.5 font-medium">目标(草案)</th>
              <th className="px-4 py-2.5 font-medium">达标</th>
            </tr>
          </thead>
          <tbody>
            {METRIC_ROWS.map((r) => {
              const v = metrics[r.key]
              const ok = r.pass(v)
              return (
                <tr key={r.key} className="border-b border-line/60 last:border-0">
                  <td className="px-4 py-2.5 text-ink-2">{r.label}</td>
                  <td className="px-4 py-2.5 tabular-nums text-ink-3">{r.baseline}</td>
                  <td className="px-4 py-2.5 font-semibold tabular-nums text-ink">{pct(v)}</td>
                  <td className="px-4 py-2.5 tabular-nums text-ink-3">{r.target}</td>
                  <td className="px-4 py-2.5">
                    <Badge tone={ok ? 'ok' : 'high'}>
                      {ok ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                      {ok ? '达标' : '待提升'}
                    </Badge>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </Card>
      <p className="text-[12.5px] text-ink-3">
        Baseline = 无枢衡(攻击直达,按全部成功的保守上界)。目标值为阶段性验收线草案,非最终承诺;
        溯源命中率@1/@3 需工具级归因金标准,本期暂未纳入主表。
      </p>

      {/* 逐样例明细 */}
      <div className="flex items-center gap-3 pt-1">
        <h3 className="text-[15px] font-semibold text-ink">逐样例</h3>
        <Segmented value={filter} onValueChange={(v) => setFilter(v as Filter)} items={FILTERS} />
      </div>
      <Card className="overflow-hidden">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-line text-left text-[13px] text-ink-3">
              <th className="px-4 py-2.5 font-medium">样例</th>
              <th className="px-4 py-2.5 font-medium">攻击类型</th>
              <th className="px-4 py-2.5 font-medium">性质</th>
              <th className="px-4 py-2.5 font-medium">期望</th>
              <th className="px-4 py-2.5 font-medium">实处置</th>
              <th className="px-4 py-2.5 font-medium">判定</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.sample_id} className="border-b border-line/60 last:border-0">
                <td className="px-4 py-2.5 font-mono text-[13px] text-ink-2">{s.sample_id}</td>
                <td className="px-4 py-2.5 text-ink-3">{s.attack_type}</td>
                <td className="px-4 py-2.5">
                  <Badge tone={s.malicious ? 'crit' : 'ok'}>{s.malicious ? '攻击' : '正常'}</Badge>
                </td>
                <td className="px-4 py-2.5">
                  <Badge tone={DISP_TONE[s.expected] ?? 'neutral'}>
                    {DISP_LABEL[s.expected] ?? s.expected}
                  </Badge>
                </td>
                <td className="px-4 py-2.5">
                  <Badge tone={DISP_TONE[s.predicted] ?? 'neutral'}>
                    {DISP_LABEL[s.predicted] ?? s.predicted}
                  </Badge>
                </td>
                <td className="px-4 py-2.5">
                  <span
                    className={cn(
                      'inline-flex items-center gap-1 text-[13px]',
                      s.decision_correct ? 'text-ok' : 'text-high',
                    )}
                  >
                    {s.decision_correct ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
                    {s.decision_correct ? '符合' : '偏差'}
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
