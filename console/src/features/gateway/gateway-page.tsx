import { type ReactNode, useRef, useState } from 'react'
import { ArrowDown, Bot, Send, Server, ShieldCheck, User } from 'lucide-react'
import { Badge, type BadgeTone, Button, Card, Input, toast } from '@/components/ui'
import { cn } from '@/lib/utils'
import { type MessageKey, useTranslation } from '@/lib/i18n'
import { type Disposition, type GatewayChatResult, sendGatewayChat } from './api'

const DISP_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
// 处置标签 key(在调用时经 t() 解析当前语言)。
const DISP_KEY: Record<Disposition, MessageKey> = {
  block: 'gateway.disp.block',
  approve: 'gateway.disp.approve',
  sanitize: 'gateway.disp.sanitize',
  allow: 'gateway.disp.allow',
}

// 一键演示样例:覆盖正常办事 + 三类典型攻击,直观看出网关分级处置。
const PRESETS: { labelKey: MessageKey; textKey: MessageKey }[] = [
  { labelKey: 'gateway.preset.normal', textKey: 'gateway.preset.normal_text' },
  { labelKey: 'gateway.preset.injection', textKey: 'gateway.preset.injection_text' },
  { labelKey: 'gateway.preset.exfil', textKey: 'gateway.preset.exfil_text' },
  { labelKey: 'gateway.preset.escalation', textKey: 'gateway.preset.escalation_text' },
]

/** 一条测试结果 = 送进去的消息 + 网关返回的完整判定链。 */
interface Trial extends GatewayChatResult {
  message: string
}

/** 流水线节点:左侧序号 + 竖线,右侧内容(仿审计链时间轴)。 */
function Stage({
  n,
  title,
  icon: Icon,
  muted,
  last,
  children,
}: {
  n: number
  title: string
  icon: typeof ShieldCheck
  muted?: boolean
  last?: boolean
  children: ReactNode
}) {
  return (
    <li className="flex gap-3">
      <div className="flex flex-col items-center">
        <span
          className={cn(
            'flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-[12px] font-semibold',
            muted ? 'bg-surface-2 text-ink-3' : 'bg-accent/12 text-accent-ink',
          )}
        >
          {n}
        </span>
        {!last && <span className="my-1 w-px flex-1 bg-line" />}
      </div>
      <div className={cn('min-w-0 flex-1 pb-4', muted && 'opacity-60')}>
        <div className="mb-1 flex items-center gap-1.5 text-[13px] font-medium text-ink-2">
          <Icon className="h-3.5 w-3.5" />
          {title}
        </div>
        {children}
      </div>
    </li>
  )
}

function TrialChain({ trial }: { trial: Trial }) {
  const { t } = useTranslation()
  const reached = trial.forwarded // 是否抵达企业智能体
  return (
    <Card className="p-4">
      <ol className="space-y-0">
        {/* ① 用户请求 */}
        <Stage n={1} title={t('gateway.stage.request')} icon={User}>
          <p className="text-[13.5px] leading-relaxed text-ink">{trial.message}</p>
        </Stage>

        {/* ② 输入闸门 */}
        <Stage n={2} title={t('gateway.stage.input_gate')} icon={ShieldCheck}>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={DISP_TONE[trial.decision]} dot>
              {t(DISP_KEY[trial.decision])}
            </Badge>
            <span className="text-[12.5px] text-ink-3">
              {t('gateway.stage.risk', { level: trial.risk_level, score: trial.max_score.toFixed(2) })}
            </span>
          </div>
          {trial.findings.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {trial.findings.map((f, i) => (
                <span
                  key={`${f.kind}-${i}`}
                  className="inline-flex items-center gap-1 rounded-xs border border-line-2 bg-surface px-2 py-0.5 text-[12px] text-ink-2"
                >
                  <span className="font-medium">{f.kind}</span>
                  <span className="text-line-3">{f.score.toFixed(2)}</span>
                </span>
              ))}
            </div>
          )}
          <p className="mt-1.5 text-[12.5px] leading-snug text-ink-3">{trial.reason}</p>
        </Stage>

        {/* ③ 转发决策 */}
        <Stage n={3} title={t('gateway.stage.forward')} icon={Server} muted={!reached}>
          {reached ? (
            <span className="inline-flex items-center gap-1.5 text-[13px] text-ok">
              <ArrowDown className="h-3.5 w-3.5" />
              {t('gateway.stage.forwarded')}
            </span>
          ) : (
            <span className="text-[13px] text-ink-3">
              {t('gateway.stage.not_forwarded', { disp: t(DISP_KEY[trial.decision]) })}
            </span>
          )}
          {trial.upstream_error && (
            <p className="mt-1 text-[12.5px] text-crit">
              {t('gateway.stage.upstream_error', { error: trial.upstream_error })}
            </p>
          )}
        </Stage>

        {/* ④ 企业智能体回复 */}
        <Stage n={4} title={t('gateway.stage.reply')} icon={Bot} muted={!reached}>
          {reached ? (
            <>
              <p className="whitespace-pre-wrap text-[13.5px] leading-relaxed text-ink">
                {trial.reply || t('gateway.stage.no_reply')}
              </p>
              {trial.tools.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {trial.tools.map((tool, i) => (
                    <span
                      key={i}
                      className="rounded-xs bg-surface-2 px-2 py-0.5 font-mono text-[12px] text-ink-2"
                    >
                      {String((tool as { tool?: unknown }).tool ?? 'tool')}
                    </span>
                  ))}
                </div>
              )}
            </>
          ) : (
            <span className="text-[13px] text-ink-3">—</span>
          )}
        </Stage>

        {/* ⑤ 出口闸门 */}
        <Stage n={5} title={t('gateway.stage.output_gate')} icon={ShieldCheck} muted={!reached} last>
          {reached && trial.output_decision ? (
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={DISP_TONE[trial.output_decision]} dot>
                {t(DISP_KEY[trial.output_decision])}
              </Badge>
              {trial.output_blocked && (
                <span className="text-[12.5px] text-crit">{t('gateway.output.blocked')}</span>
              )}
              {trial.output_sanitized && (
                <span className="text-[12.5px] text-med">{t('gateway.output.sanitized')}</span>
              )}
              {!trial.output_blocked && !trial.output_sanitized && (
                <span className="text-[12.5px] text-ink-3">
                  {trial.output_reason || t('gateway.output.clean')}
                </span>
              )}
            </div>
          ) : (
            <span className="text-[13px] text-ink-3">—</span>
          )}
        </Stage>
      </ol>
    </Card>
  )
}

export function GatewayPage() {
  const { t } = useTranslation()
  const [input, setInput] = useState('')
  const [pending, setPending] = useState(false)
  const [trials, setTrials] = useState<Trial[]>([])
  const seq = useRef(0)

  const send = async (text: string) => {
    const message = text.trim()
    if (!message || pending) return
    setPending(true)
    seq.current += 1
    try {
      const res = await sendGatewayChat(`web-gw-${seq.current}`, message)
      setTrials((prev) => [{ ...res, message }, ...prev].slice(0, 20))
      setInput('')
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-4">
      <p className="mb-3 text-[13px] text-ink-3">{t('gateway.intro')}</p>

      {/* 输入 + 一键样例 */}
      <Card className="space-y-3 p-4">
        <div className="flex items-center gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send(input)}
            placeholder={t('gateway.input.placeholder')}
            className="flex-1"
          />
          <Button variant="primary" onClick={() => send(input)} disabled={pending || !input.trim()}>
            <Send className="mr-1.5 h-3.5 w-3.5" />
            {pending ? t('gateway.sending') : t('gateway.send')}
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[12px] text-ink-3">{t('gateway.presets')}</span>
          {PRESETS.map((p) => (
            <button
              key={p.labelKey}
              type="button"
              onClick={() => send(t(p.textKey))}
              disabled={pending}
              className="rounded-full border border-line-2 px-2.5 py-1 text-[12.5px] text-ink-3 transition-colors hover:border-line-3 hover:text-ink-2 disabled:opacity-50"
            >
              {t(p.labelKey)}
            </button>
          ))}
        </div>
      </Card>

      {/* 判定链结果(最新在前) */}
      <div className="mt-4 space-y-3">
        {trials.length === 0 ? (
          <p className="py-10 text-center text-[13px] text-ink-3">{t('gateway.empty')}</p>
        ) : (
          trials.map((trial, i) => <TrialChain key={`${trial.session_id}-${i}`} trial={trial} />)
        )}
      </div>
    </div>
  )
}
