import { useEffect, useMemo, useRef, useState } from 'react'
import {
  ArrowUp,
  Check,
  ChevronDown,
  CircleAlert,
  Loader2,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react'
import { Badge, type BadgeTone, Button, Card, Switch, toast } from '@/components/ui'
import { useNavigateFeature } from '@/lib/nav'
import {
  type ActionRisk,
  type AssistantStep,
  type AssistantTool,
  type ChatMessage,
  KIND_LABEL,
  PAGE_TO_FEATURE,
  type ProposalState,
  type ProposedAction,
  RISK_LABEL,
  type ToolKind,
  type UiDirective,
} from './data'
import { confirmAction, sendChat, undoAction, useAssistantTools } from './use-assistant'

const RISK_TONE: Record<ActionRisk, BadgeTone> = { read_only: 'ok', normal: 'med', high: 'crit' }
const KIND_ORDER: ToolKind[] = ['ui', 'read', 'write']

// 对话式快捷意图(点选即发送)—— 覆盖查/办/跳三类,降低"不知道能问什么"的认知负担。
const QUICK_INTENTS = [
  '看一下安全总览',
  '最近有哪些被拦截的事件?',
  '列出待审批的账号',
  '把审计会话链都校验一遍',
]

const newId = (): string =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

function toProposalState(a: ProposedAction): ProposalState {
  return {
    id: newId(),
    action: a,
    editedArgs: { ...a.args },
    status: 'editing',
    resultSummary: '',
    actionId: null,
    reversible: a.reversible,
    undoPreview: '',
  }
}

export function AssistantPage() {
  const navigate = useNavigateFeature()
  const tools = useAssistantTools().data ?? []
  // 一次挂载一条会话:对话 / 确认 / 撤销 / 审计共用同一 session,可在审计链里整段溯源。
  const sessionId = useMemo(() => `assistant:web:${newId().slice(0, 8)}`, [])

  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  // 新消息到达后滚到底(对话流的基本期待)。
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages])

  const patchProposal = (propId: string, patch: Partial<ProposalState>) =>
    setMessages((ms) =>
      ms.map((m) =>
        m.role === 'assistant'
          ? { ...m, proposals: m.proposals.map((p) => (p.id === propId ? { ...p, ...patch } : p)) }
          : m,
      ),
    )

  // ui 指令由前端执行:导航/筛选/开面板真的把界面切过去。
  const runDirective = (d: UiDirective) => {
    if (d.tool === 'filter_events') {
      navigate('events')
      toast.success('已切到实时事件', { description: describeArgs(d.args) || '已应用筛选' })
      return
    }
    if (d.tool === 'open_settings_panel') {
      navigate('settings')
      toast.success('已打开系统设置')
      return
    }
    const feat = PAGE_TO_FEATURE[String(d.args.page ?? '')]
    if (feat) {
      navigate(feat)
      toast.success(`已为你打开「${d.label}」`)
    }
  }

  const send = async (raw: string) => {
    const text = raw.trim()
    if (!text || busy) return
    const aid = newId()
    setMessages((m) => [
      ...m,
      { id: newId(), role: 'user', text },
      {
        id: aid,
        role: 'assistant',
        text: '',
        pending: true,
        blocked: false,
        steps: [],
        proposals: [],
      },
    ])
    setInput('')
    setBusy(true)
    try {
      const res = await sendChat(text, sessionId)
      res.ui_directives.forEach(runDirective)
      const proposals = res.proposed_actions.map(toProposalState)
      setMessages((m) =>
        m.map((x) =>
          x.id === aid && x.role === 'assistant'
            ? {
                ...x,
                pending: false,
                text: res.reply,
                blocked: res.blocked,
                steps: res.steps,
                proposals,
              }
            : x,
        ),
      )
    } catch (e) {
      setMessages((m) =>
        m.map((x) =>
          x.id === aid && x.role === 'assistant'
            ? { ...x, pending: false, text: `出错:${(e as Error).message}` }
            : x,
        ),
      )
    } finally {
      setBusy(false)
    }
  }

  const confirm = async (p: ProposalState) => {
    patchProposal(p.id, { status: 'confirming' })
    try {
      const r = await confirmAction(p.action.action_token, p.editedArgs, sessionId)
      if (r.ok) {
        patchProposal(p.id, {
          status: 'done',
          resultSummary: r.summary,
          actionId: r.action_id,
          reversible: r.reversible,
          undoPreview: r.undo_preview,
        })
        toast.success('已执行', { description: r.summary })
      } else {
        patchProposal(p.id, { status: 'editing' })
        toast.error('执行未成功', { description: r.summary })
      }
    } catch (e) {
      patchProposal(p.id, { status: 'editing' })
      toast.error((e as Error).message)
    }
  }

  const undo = async (p: ProposalState) => {
    if (!p.actionId) return
    patchProposal(p.id, { status: 'undoing' })
    try {
      const r = await undoAction(p.actionId, sessionId)
      if (r.ok) {
        patchProposal(p.id, { status: 'undone', resultSummary: r.summary })
        toast.success('已撤销', { description: r.summary })
      } else {
        patchProposal(p.id, { status: 'done' })
        toast.error('撤销未成功', { description: r.summary })
      }
    } catch (e) {
      patchProposal(p.id, { status: 'done' })
      toast.error((e as Error).message)
    }
  }

  return (
    <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[minmax(0,1fr)_300px]">
      {/* 对话流 */}
      <section className="flex min-h-0 flex-col">
        <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-5">
          <div className="mx-auto max-w-3xl">
            {messages.length === 0 ? (
              <Welcome onPick={send} />
            ) : (
              <div className="space-y-5">
                {messages.map((m) =>
                  m.role === 'user' ? (
                    <UserBubble key={m.id} text={m.text} />
                  ) : (
                    <AssistantBubble
                      key={m.id}
                      msg={m}
                      onConfirm={confirm}
                      onCancel={(p) => patchProposal(p.id, { status: 'cancelled' })}
                      onUndo={undo}
                      onEdit={(p, k, v) =>
                        patchProposal(p.id, { editedArgs: { ...p.editedArgs, [k]: v } })
                      }
                    />
                  ),
                )}
              </div>
            )}
          </div>
        </div>

        <Composer value={input} onChange={setInput} onSend={() => send(input)} busy={busy} />
      </section>

      {/* 可调工具侧栏 */}
      <ToolsSidebar tools={tools} />
    </div>
  )
}

// ─────────────────────────── 子组件 ───────────────────────────

function Welcome({ onPick }: { onPick: (s: string) => void }) {
  return (
    <div className="grid place-items-center px-4 py-12 text-center">
      <div className="max-w-md space-y-3">
        <div className="mx-auto grid h-11 w-11 place-items-center rounded-full bg-accent/10 text-accent-ink">
          <Sparkles className="h-5 w-5" />
        </div>
        <h2 className="text-[15px] font-semibold text-ink">AI 操作助手</h2>
        <p className="text-[13px] leading-relaxed text-ink-3">
          用自然语言下达意图,助手在你的权限内查询数据、切换界面、办理操作。
          写操作会先给可编辑提案,确认后执行、可一键撤销 —— 全程在闸门内、可审计。
        </p>
        <div className="flex flex-wrap justify-center gap-1.5 pt-1">
          {QUICK_INTENTS.map((s) => (
            <button
              key={s}
              onClick={() => onPick(s)}
              className="focus-ring rounded-full border border-line-2 px-3 py-1 text-[12.5px] text-ink-3 transition-colors hover:border-line-3 hover:text-ink-2"
            >
              {s}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

function UserBubble({ text }: { text: string }) {
  return (
    <div className="flex justify-end">
      <div className="max-w-[85%] whitespace-pre-wrap rounded-2xl rounded-br-md bg-accent px-3.5 py-2 text-[14px] leading-relaxed text-white">
        {text}
      </div>
    </div>
  )
}

interface AssistantBubbleProps {
  msg: Extract<ChatMessage, { role: 'assistant' }>
  onConfirm: (p: ProposalState) => void
  onCancel: (p: ProposalState) => void
  onUndo: (p: ProposalState) => void
  onEdit: (p: ProposalState, key: string, value: unknown) => void
}

function AssistantBubble({ msg, onConfirm, onCancel, onUndo, onEdit }: AssistantBubbleProps) {
  return (
    <div className="flex gap-2.5">
      <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full bg-accent/10 text-accent-ink">
        <Sparkles className="h-3.5 w-3.5" />
      </div>
      <div className="min-w-0 flex-1 space-y-2.5">
        {msg.pending ? (
          <Typing />
        ) : (
          <>
            {msg.blocked && (
              <Badge tone="crit" dot>
                已被安全网关拦截
              </Badge>
            )}
            {msg.text && (
              <div className="whitespace-pre-wrap text-[14px] leading-relaxed text-ink-2">
                {msg.text}
              </div>
            )}
            {msg.steps.length > 0 && <Trace steps={msg.steps} />}
            {msg.proposals.map((p) => (
              <ProposalCard
                key={p.id}
                p={p}
                onConfirm={() => onConfirm(p)}
                onCancel={() => onCancel(p)}
                onUndo={() => onUndo(p)}
                onEdit={(k, v) => onEdit(p, k, v)}
              />
            ))}
          </>
        )}
      </div>
    </div>
  )
}

function Typing() {
  return (
    <div className="flex items-center gap-2 text-[13px] text-ink-3">
      <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />
      <span>思考中…</span>
    </div>
  )
}

function Trace({ steps }: { steps: AssistantStep[] }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-md border border-line bg-subtle">
      <button
        onClick={() => setOpen((v) => !v)}
        className="focus-ring flex w-full items-center gap-1.5 px-2.5 py-1.5 text-[12px] text-ink-3"
      >
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? '' : '-rotate-90'}`} />
        执行轨迹 · {steps.length} 步
      </button>
      {open && (
        <div className="space-y-1 border-t border-line px-2.5 py-2">
          {steps.map((s, i) => (
            <div key={i} className="flex items-start gap-2 text-[12px]">
              {s.ok ? (
                <Check className="mt-0.5 h-3 w-3 shrink-0 text-ok" />
              ) : (
                <X className="mt-0.5 h-3 w-3 shrink-0 text-crit" />
              )}
              <span className="shrink-0 text-ink-2">{s.label}</span>
              <span className="min-w-0 truncate text-ink-mute">{s.detail}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

interface ProposalCardProps {
  p: ProposalState
  onConfirm: () => void
  onCancel: () => void
  onUndo: () => void
  onEdit: (key: string, value: unknown) => void
}

function ProposalCard({ p, onConfirm, onCancel, onUndo, onEdit }: ProposalCardProps) {
  const tone: BadgeTone =
    p.action.risk === 'high' ? 'crit' : p.action.risk === 'normal' ? 'med' : 'ok'
  const editing = p.status === 'editing'
  const entries = Object.entries(p.editedArgs)

  return (
    <Card className="overflow-hidden border border-line">
      <div className="flex items-center justify-between gap-2 border-b border-line bg-subtle px-3.5 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-accent" />
          <span className="truncate text-[13px] font-medium text-ink">{p.action.label}</span>
          <Badge tone={tone}>{RISK_LABEL[p.action.risk as ActionRisk] ?? p.action.risk}</Badge>
        </div>
        <code className="shrink-0 text-[11px] text-ink-mute">{p.action.tool}</code>
      </div>

      <div className="space-y-2.5 p-3.5">
        <p className="flex items-start gap-1.5 text-[12px] leading-snug text-ink-3">
          <CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-med" />
          {p.action.note}
        </p>

        {entries.length > 0 && (
          <div className="space-y-1.5">
            {entries.map(([k, v]) => (
              <FieldRow
                key={k}
                name={k}
                value={v}
                disabled={!editing}
                onChange={(nv) => onEdit(k, nv)}
              />
            ))}
          </div>
        )}

        {/* 执行结果(成功/撤销)摘要 */}
        {(p.status === 'done' || p.status === 'undoing' || p.status === 'undone') &&
          p.resultSummary && (
            <div className="rounded-md bg-surface-2 px-3 py-2 text-[12.5px] text-ink-2">
              {p.resultSummary}
            </div>
          )}

        <div className="flex items-center gap-2 pt-0.5">
          {editing && (
            <>
              <Button
                variant={p.action.risk === 'high' ? 'danger' : 'primary'}
                size="sm"
                onClick={onConfirm}
              >
                确认执行
              </Button>
              <Button variant="ghost" size="sm" onClick={onCancel}>
                取消
              </Button>
            </>
          )}
          {p.status === 'confirming' && (
            <span className="flex items-center gap-1.5 text-[12px] text-ink-3">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> 执行中…
            </span>
          )}
          {p.status === 'cancelled' && <span className="text-[12px] text-ink-mute">已取消</span>}
          {p.status === 'done' && p.reversible && p.actionId && (
            <Button variant="secondary" size="sm" onClick={onUndo}>
              <RotateCcw className="mr-1 h-3.5 w-3.5" />
              撤销{p.undoPreview ? `(${p.undoPreview})` : ''}
            </Button>
          )}
          {p.status === 'done' && !(p.reversible && p.actionId) && (
            <span className="flex items-center gap-1 text-[12px] text-ok">
              <Check className="h-3.5 w-3.5" /> 已执行
            </span>
          )}
          {p.status === 'undoing' && (
            <span className="flex items-center gap-1.5 text-[12px] text-ink-3">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> 撤销中…
            </span>
          )}
          {p.status === 'undone' && (
            <span className="flex items-center gap-1 text-[12px] text-ink-mute">
              <RotateCcw className="h-3.5 w-3.5" /> 已撤销
            </span>
          )}
        </div>
      </div>
    </Card>
  )
}

function FieldRow({
  name,
  value,
  disabled,
  onChange,
}: {
  name: string
  value: unknown
  disabled: boolean
  onChange: (v: unknown) => void
}) {
  return (
    <div className="flex items-center gap-3">
      <label className="w-28 shrink-0 truncate text-[12.5px] text-ink-3">{name}</label>
      {typeof value === 'boolean' ? (
        <Switch checked={value} disabled={disabled} onCheckedChange={onChange} />
      ) : typeof value === 'number' ? (
        <input
          type="number"
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.valueAsNumber)}
          className="focus-ring h-7 w-full rounded-sm border border-line-2 bg-surface px-2.5 text-[13px] text-ink disabled:opacity-60"
        />
      ) : (
        <input
          type="text"
          value={String(value ?? '')}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          className="focus-ring h-7 w-full rounded-sm border border-line-2 bg-surface px-2.5 text-[13px] text-ink disabled:opacity-60"
        />
      )}
    </div>
  )
}

function Composer({
  value,
  onChange,
  onSend,
  busy,
}: {
  value: string
  onChange: (v: string) => void
  onSend: () => void
  busy: boolean
}) {
  return (
    <div className="border-t border-line bg-surface px-4 py-3">
      <div className="mx-auto max-w-3xl">
        <div className="flex items-end gap-2">
          <textarea
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                onSend()
              }
            }}
            rows={1}
            placeholder="下达意图,例如:把待审批的账号都通过(Enter 发送,Shift+Enter 换行)"
            className="focus-ring max-h-32 min-h-[40px] flex-1 resize-none rounded-md border border-line-2 bg-surface px-3 py-2 text-[14px] text-ink transition-colors placeholder:text-ink-mute hover:border-line-3"
          />
          <Button variant="primary" size="icon" onClick={onSend} disabled={busy || !value.trim()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowUp className="h-4 w-4" />}
          </Button>
        </div>
        <p className="mt-1.5 text-[11px] leading-snug text-ink-mute">
          助手在权限闸门内操作,工具调用与写操作均经审计、可一键撤销;AI 可能出错,请核对结果。
        </p>
      </div>
    </div>
  )
}

function ToolsSidebar({ tools }: { tools: AssistantTool[] }) {
  const byKind = KIND_ORDER.map((k) => ({
    kind: k,
    items: tools.filter((t) => t.kind === k),
  })).filter((g) => g.items.length > 0)
  return (
    <aside className="hidden min-h-0 flex-col border-l border-line bg-subtle lg:flex">
      <div className="flex items-center gap-1.5 border-b border-line px-4 py-3 text-[13px] font-medium text-ink-2">
        <Sparkles className="h-3.5 w-3.5 text-accent" />
        可调工具 · {tools.length}
      </div>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-3">
        <p className="text-[11.5px] leading-snug text-ink-mute">
          助手能调的 = 当前角色能点的(后端按权限点过滤,与界面同一套闸门)。
        </p>
        {byKind.map((g) => (
          <div key={g.kind} className="space-y-1.5">
            <div className="px-1 text-[11px] font-medium uppercase tracking-wide text-ink-mute">
              {KIND_LABEL[g.kind]} · {g.items.length}
            </div>
            {g.items.map((t) => (
              <div key={t.name} className="rounded-md border border-line bg-surface px-2.5 py-2">
                <div className="flex items-center gap-1.5">
                  <span className="min-w-0 truncate text-[12.5px] font-medium text-ink">
                    {t.label}
                  </span>
                  <Badge tone={RISK_TONE[t.risk]}>{RISK_LABEL[t.risk]}</Badge>
                </div>
                <p className="mt-0.5 line-clamp-2 text-[11.5px] leading-snug text-ink-3">
                  {t.description}
                </p>
              </div>
            ))}
          </div>
        ))}
      </div>
    </aside>
  )
}

function describeArgs(args: Record<string, unknown>): string {
  return Object.entries(args)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(' · ')
}
