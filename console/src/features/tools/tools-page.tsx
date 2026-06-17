import { useMemo, useState } from 'react'
import { Plug, ShieldX } from 'lucide-react'
import { Badge, type BadgeTone, Card, Segmented } from '@/components/ui'
import { TOOL_CALLS, type Disposition, type Trust } from './data'

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
const TRUST_LABEL: Record<Trust, string> = { untrusted: '不可信', semi: '半可信', trusted: '可信' }
const TRUST_TONE: Record<Trust, BadgeTone> = { untrusted: 'crit', semi: 'med', trusted: 'ok' }

type Filter = 'all' | 'held' | 'allow'
const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'held', label: '已管控' },
  { value: 'allow', label: '放行' },
]

export function ToolsPage() {
  const [filter, setFilter] = useState<Filter>('all')
  const rows = useMemo(
    () =>
      TOOL_CALLS.filter((c) =>
        filter === 'all' ? true : filter === 'allow' ? c.decision === 'allow' : c.decision !== 'allow',
      ),
    [filter],
  )
  const held = TOOL_CALLS.filter((c) => c.decision !== 'allow').length

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 className="text-[15px] font-semibold text-ink">工具调用管控</h2>
        <span className="text-[13px] text-ink-3">
          每次高危工具调用都过「归因 → 评分 → 任务链 → 策略 → 沙箱执行」;近 {TOOL_CALLS.length}{' '}
          次,其中 <span className="font-medium text-crit">{held}</span> 次被管控(阻断/审批)。
        </span>
      </div>

      <div className="flex items-center gap-3">
        <Segmented value={filter} onValueChange={(v) => setFilter(v as Filter)} items={FILTERS} />
      </div>

      <Card className="overflow-hidden">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-line text-left text-[13px] text-ink-3">
              <th className="px-4 py-2.5 font-medium">时间</th>
              <th className="px-4 py-2.5 font-medium">工具 · 参数</th>
              <th className="px-4 py-2.5 font-medium">来源</th>
              <th className="px-4 py-2.5 font-medium">风险</th>
              <th className="px-4 py-2.5 font-medium">归因</th>
              <th className="px-4 py-2.5 font-medium">处置</th>
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
                  <Badge tone={TRUST_TONE[c.source_trust]}>{TRUST_LABEL[c.source_trust]}</Badge>
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
                    {DISP_LABEL[c.decision]}
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

      <div className="flex items-center gap-2 pb-2 text-[12.5px] text-ink-3">
        <ShieldX className="h-3.5 w-3.5" />
        放行的高危调用经受限执行器(`restricted`)沙箱边界 + 超时执行;<Plug className="h-3.5 w-3.5" />
        管线入口 `evaluate_intent` / `/tools/call`。
      </div>
    </div>
  )
}
