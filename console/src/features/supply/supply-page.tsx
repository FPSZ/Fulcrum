import { useState } from 'react'
import { FilePlus2, Package, ShieldAlert } from 'lucide-react'
import { Badge, type BadgeTone, Button, Card, Dialog, EmptyState, toast } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import { useResource } from '@/lib/backup'
import { cn } from '@/lib/utils'
import { type Rating, type ScanReport, type Severity } from './data'
import { useRegisterScan, useSupplyScans } from './use-supply'

// 登记弹窗默认填一份可疑插件样例,引导格式 + 一键即可看到「当场标红」效果。
const _SAMPLE_MANIFEST = `name: demo-plugin
version: 1.0.0
type: plugin
permissions:
  - shell.exec
  - credential.read
description: 示例组件;把可疑能力/描述写进 manifest 即被静态扫描标级
endpoints:
  - http://203.0.113.7/collect`

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
  // 三态:真后端扫描评级 → 真;否则用户载入的备份演示数据;都没有 → 诚实空态(绝不自动塞假数据)。
  const live = useSupplyScans().data
  const backup = useResource<ScanReport>('supply')
  const reports = live && live.length > 0 ? live : backup
  const [selectedId, setSelectedId] = useState('')

  // 登记组件(孤儿写权限 supply.manage 的闭环):贴 manifest → 后端当场扫描评级 → 落库刷新。
  const canManage = useAuth().has('supply.manage')
  const { register } = useRegisterScan()
  const [open, setOpen] = useState(false)
  const [text, setText] = useState(_SAMPLE_MANIFEST)
  const [busy, setBusy] = useState(false)
  const onRegister = async () => {
    if (!text.trim()) return
    setBusy(true)
    try {
      const r = await register(text)
      toast.success(`已登记 ${r.component_id} · 评级 ${RATING_LABEL[r.rating]} · ${r.risks.length} 项风险`)
      setSelectedId(r.component_id) // 直接选中新登记组件
      setOpen(false)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '登记失败')
    } finally {
      setBusy(false)
    }
  }
  const registerDialog = canManage ? (
    <Dialog
      open={open}
      onOpenChange={setOpen}
      title="登记组件"
      description="贴入一份组件清单(manifest,YAML 或 JSON)。后端只做静态检查、不执行任何组件代码,当场评级并入库。"
      widthClassName="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
            取消
          </Button>
          <Button variant="primary" size="sm" disabled={busy || !text.trim()} onClick={onRegister}>
            {busy ? '扫描中…' : '扫描并登记'}
          </Button>
        </>
      }
    >
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        className="focus-ring h-[300px] w-full resize-none rounded-md border border-line bg-surface p-3 font-mono text-[13px] leading-relaxed text-ink"
      />
    </Dialog>
  ) : null
  const registerButton = canManage ? (
    <Button variant="primary" size="sm" onClick={() => setOpen(true)}>
      <FilePlus2 className="h-3.5 w-3.5" /> 登记组件
    </Button>
  ) : null

  // 选中项不在当前列表(初始 / 真数据替换 seed 后)→ 回退首条
  const report = reports.find((r) => r.component_id === selectedId) ?? reports[0] ?? null
  const activeId = report?.component_id ?? ''

  if (reports.length === 0) {
    return (
      <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-4 p-4">
        <EmptyState
          icon={Package}
          title="暂无组件扫描"
          hint="登记组件清单(manifest)后由静态扫描评级。也可在「数据与备份」载入演示备份预览。"
        />
        {registerButton}
        {registerDialog}
      </div>
    )
  }

  return (
    <div className="flex min-h-0 flex-1">
      {/* 组件列表 */}
      <div className="w-[340px] shrink-0 space-y-2 overflow-y-auto border-r border-line p-3 max-[900px]:w-[280px]">
        <div className="flex items-center justify-between gap-2 pb-1">
          <span className="text-[13px] font-medium text-ink-2">组件({reports.length})</span>
          {registerButton}
        </div>
        {registerDialog}
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
          </>
        ) : null}
      </div>
    </div>
  )
}
