import { useState } from 'react'
import { CornerDownLeft, Lock, Sparkles, Wand2 } from 'lucide-react'
import { Badge, type BadgeTone, Button, Card, Dialog, Input, toast } from '@/components/ui'
import { useNavigateFeature } from '@/lib/nav'
import {
  actionNav,
  isExecutable,
  RISK_LABEL,
  SAMPLE_INTENTS,
  seedActions,
  type ActionRisk,
  type PlanResult,
} from './data'
import { planIntent, useAssistantActions } from './use-assistant'

const RISK_TONE: Record<ActionRisk, BadgeTone> = { read_only: 'ok', normal: 'med', high: 'crit' }

/** 规划结果 → 处置标签:越权拒绝 / 无法规划 / 需二次确认 / 可执行。 */
function disposition(plan: PlanResult): { tone: BadgeTone; label: string } {
  if (plan.denied) return { tone: 'crit', label: '越权拒绝' }
  if (!plan.ok) return { tone: 'med', label: '无法规划' }
  if (plan.requires_confirmation) return { tone: 'high', label: '需二次确认' }
  return { tone: 'ok', label: '可执行' }
}

export function AssistantPage() {
  const navigate = useNavigateFeature()
  // 接真后端:有动作目录(按角色权限过滤)用真;无权限/不可达/空 → 回退各模块聚合的 seed。
  const live = useAssistantActions().data
  const actions = live && live.length > 0 ? live : seedActions()

  const [intent, setIntent] = useState('')
  const [planning, setPlanning] = useState(false)
  const [plan, setPlan] = useState<PlanResult | null>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)

  const onPlan = async () => {
    const text = intent.trim()
    if (!text || planning) return
    setPlanning(true)
    setPlan(null)
    try {
      setPlan(await planIntent(text))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setPlanning(false)
    }
  }

  // 真执行:只读导航/筛选 → 切到对应页;高危写操作执行入口排后,诚实提示走各自守卫端点。
  const execute = (p: PlanResult) => {
    setConfirmOpen(false)
    const target = p.action_id ? actionNav()[p.action_id] : undefined
    if (target) {
      navigate(target)
      toast.success(`已为你打开「${p.label}」`)
    } else {
      toast('该高危写操作的执行入口排后', {
        description: '请在对应页手动确认,并命中受 RBAC 守卫的端点(纵深防御,不靠助手自觉)。',
      })
    }
  }

  const onRun = (p: PlanResult) => (p.requires_confirmation ? setConfirmOpen(true) : execute(p))

  const disp = plan ? disposition(plan) : null

  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-4">
      <p className="mb-4 text-[13px] text-ink-3">
        用自然语言下达意图,助手在<span className="font-medium text-ink-2">权限闸门内</span>
        规划受治理动作:只读可直接执行,高危必须二次确认,每次规划都写入审计链。
      </p>

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* 左:意图输入 + 规划结果 */}
        <div className="space-y-4">
          <Card className="space-y-3 p-4">
            <label className="text-[13px] font-medium text-ink-2">下达意图</label>
            <div className="flex items-center gap-2">
              <Input
                value={intent}
                onChange={(e) => setIntent(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && onPlan()}
                placeholder="例如:把实时事件按严重等级筛一下,只看阻断"
                className="flex-1"
              />
              <Button variant="primary" onClick={onPlan} disabled={planning || !intent.trim()}>
                <Wand2 className="mr-1.5 h-3.5 w-3.5" />
                {planning ? '规划中…' : '规划'}
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[12px] text-ink-3">试试:</span>
              {SAMPLE_INTENTS.map((s) => (
                <button
                  key={s}
                  onClick={() => setIntent(s)}
                  className="rounded-full border border-line-2 px-2.5 py-1 text-[12.5px] text-ink-3 transition-colors hover:border-line-3 hover:text-ink-2"
                >
                  {s}
                </button>
              ))}
            </div>
          </Card>

          {disp && plan && (
            <Card className="space-y-3 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={disp.tone} dot>
                  {disp.label}
                </Badge>
                {plan.label && <span className="text-[14px] font-medium text-ink">{plan.label}</span>}
                {plan.action_id && (
                  <code className="text-[12px] text-ink-3">{plan.action_id}</code>
                )}
                {plan.risk && (plan.risk as ActionRisk) in RISK_TONE && (
                  <Badge tone={RISK_TONE[plan.risk as ActionRisk]}>
                    {RISK_LABEL[plan.risk as ActionRisk]}
                  </Badge>
                )}
              </div>

              <p className="text-[13px] leading-relaxed text-ink-2">{plan.reason}</p>

              {Object.keys(plan.args).length > 0 && (
                <pre className="overflow-x-auto rounded-md bg-surface-2 px-3 py-2 font-mono text-[12px] text-ink-2">
                  {JSON.stringify(plan.args, null, 2)}
                </pre>
              )}

              {plan.ok && (
                <div className="flex items-center gap-2 pt-1">
                  <Button
                    variant={plan.requires_confirmation ? 'danger' : 'primary'}
                    onClick={() => onRun(plan)}
                  >
                    {plan.requires_confirmation ? (
                      <Lock className="mr-1.5 h-3.5 w-3.5" />
                    ) : (
                      <CornerDownLeft className="mr-1.5 h-3.5 w-3.5" />
                    )}
                    {plan.requires_confirmation
                      ? '二次确认并执行'
                      : isExecutable(plan.action_id)
                        ? '执行(打开页面)'
                        : '执行'}
                  </Button>
                  {!isExecutable(plan.action_id) && (
                    <span className="text-[12px] text-ink-3">写操作执行入口排后,见弹窗说明</span>
                  )}
                </div>
              )}
            </Card>
          )}
        </div>

        {/* 右:当前角色能调的动作目录 */}
        <Card className="h-fit p-4">
          <div className="mb-2 flex items-center gap-1.5 text-[13px] font-medium text-ink-2">
            <Sparkles className="h-3.5 w-3.5 text-accent" />
            可调动作 · {actions.length}
          </div>
          <p className="mb-3 text-[12px] leading-snug text-ink-3">
            助手能调的动作 = 当前角色能点的按钮(后端按权限点过滤,与界面同一套闸门)。
          </p>
          <div className="space-y-2">
            {actions.map((a) => (
              <div key={a.id} className="rounded-md border border-line/60 px-3 py-2">
                <div className="flex items-center gap-2">
                  <span className="text-[13px] font-medium text-ink">{a.label}</span>
                  <Badge tone={RISK_TONE[a.risk]}>{RISK_LABEL[a.risk]}</Badge>
                </div>
                <p className="mt-0.5 text-[12px] leading-snug text-ink-3">{a.description}</p>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Dialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="高危动作 · 二次确认"
        description={plan ? `将要执行:${plan.label}` : undefined}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmOpen(false)}>
              取消
            </Button>
            <Button variant="danger" onClick={() => plan && execute(plan)}>
              确认执行
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-[13px] leading-relaxed text-ink-2">
          <p>{plan?.reason}</p>
          {plan && Object.keys(plan.args).length > 0 && (
            <pre className="overflow-x-auto rounded-md bg-surface-2 px-3 py-2 font-mono text-[12px]">
              {JSON.stringify(plan.args, null, 2)}
            </pre>
          )}
          <p className="text-[12px] text-ink-3">
            高危动作会削弱防护,必须由你确认。执行将命中该动作受 RBAC 守卫的端点并写入审计链。
          </p>
        </div>
      </Dialog>
    </div>
  )
}
