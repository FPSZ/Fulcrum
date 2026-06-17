import { useState } from 'react'
import { Package, ShieldAlert } from 'lucide-react'
import { Badge, type BadgeTone, Card } from '@/components/ui'
import { cn } from '@/lib/utils'
import { SCAN_REPORTS, type Rating, type Severity } from './data'
import { useSupplyScans } from './use-supply'

const RATING_TONE: Record<Rating, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const RATING_LABEL: Record<Rating, string> = {
  block: '阻断',
  approve: '需复核',
  sanitize: '净化',
  allow: '放行',
}
const SEV_TONE: Record<Severity, BadgeTone> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'neutral',
}

export function SupplyPage() {
  // 接真后端:有真实扫描评级则用真;无权限/不可达/空 → 回退演示 seed。
  const live = useSupplyScans().data
  const reports = live && live.length > 0 ? live : SCAN_REPORTS
  const [selectedId, setSelectedId] = useState('')
  // 选中项不在当前列表(初始 / 真数据替换 seed 后)→ 回退首条
  const report = reports.find((r) => r.component_id === selectedId) ?? reports[0] ?? null
  const activeId = report?.component_id ?? ''

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
                {RATING_LABEL[r.rating]}
              </Badge>
            </div>
            <p className="mt-1.5 text-[12px] text-ink-3">
              {r.kind} · {r.risks.length} 项风险
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
                评级:{RATING_LABEL[report.rating]}
              </Badge>
              <span className="text-[13px] text-ink-3">{report.kind} · {report.risks.length} 项风险</span>
            </div>
            <p className="mt-1 text-[12.5px] text-ink-3">
              静态扫描(不执行组件代码):声明权限 / 可疑描述 / 外联端点 / 依赖来源 → 按最严重项评级。
            </p>

            <Card className="mt-3 overflow-hidden">
              <table className="w-full text-[14px]">
                <thead>
                  <tr className="border-b border-line text-left text-[13px] text-ink-3">
                    <th className="px-4 py-2.5 font-medium">风险项</th>
                    <th className="px-4 py-2.5 font-medium">严重度</th>
                    <th className="px-4 py-2.5 font-medium">分值</th>
                    <th className="px-4 py-2.5 font-medium">说明</th>
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
            <p className="mt-3 flex items-center gap-2 text-[12.5px] text-ink-3">
              <Package className="h-3.5 w-3.5" />
              扫描入口:<code className="text-ink-2">python -m fulcrum.scan &lt;manifest&gt;</code>(组件上线的离线关切,不在每请求管线内)
            </p>
          </>
        ) : null}
      </div>
    </div>
  )
}
