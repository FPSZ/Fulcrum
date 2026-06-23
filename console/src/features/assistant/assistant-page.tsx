import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { ArrowUp, Check, ChevronDown, Loader2, RotateCcw, Sparkles, X } from 'lucide-react'
import { toast } from '@/components/ui'
import { useNavigateFeature } from '@/lib/nav'
import {
  type AssistantStep,
  type ChatMessage,
  PAGE_TO_FEATURE,
  type ProposalState,
  type ProposedAction,
  type UiDirective,
} from './data'
import { Markdown } from './markdown'
import { confirmAction, sendChat, undoAction } from './use-assistant'

// 起步意图(空态建议)—— 覆盖查/办/跳,克制不堆砌。
const SUGGESTIONS = [
  '看一下安全总览',
  '最近有哪些被拦截的事件?',
  '列出待审批的账号',
  '把上游网关名称改一下',
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
  const sessionId = useMemo(() => `assistant:web:${newId().slice(0, 8)}`, [])

  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [busy, setBusy] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages])

  const patchProposal = useCallback((propId: string, patch: Partial<ProposalState>) => {
    setMessages((ms) =>
      ms.map((m) =>
        m.role === 'assistant'
          ? { ...m, proposals: m.proposals.map((p) => (p.id === propId ? { ...p, ...patch } : p)) }
          : m,
      ),
    )
  }, [])

  const runDirective = useCallback(
    (d: UiDirective) => {
      if (d.tool === 'filter_events') {
        navigate('events')
        toast.success('已切到实时事件')
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
    },
    [navigate],
  )

  const send = useCallback(
    async (raw: string) => {
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
    },
    [busy, runDirective, sessionId],
  )

  const confirm = useCallback(
    async (p: ProposalState) => {
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
    },
    [patchProposal, sessionId],
  )

  const undo = useCallback(
    async (p: ProposalState) => {
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
    },
    [patchProposal, sessionId],
  )

  const empty = messages.length === 0

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-canvas">
      {empty ? (
        <div className="flex min-h-0 flex-1 flex-col items-center justify-center px-4 pb-16">
          <div className="w-full max-w-[840px]">
            <div className="mb-7 flex flex-col items-center gap-3 text-center">
              <div className="grid h-12 w-12 place-items-center rounded-2xl bg-accent/10 text-accent">
                <Sparkles className="h-6 w-6" />
              </div>
              <h1 className="text-[28px] font-semibold tracking-tight text-ink">
                需要我帮你做点什么?
              </h1>
              <p className="text-[15px] text-ink-3">
                用自然语言下达意图,我在你的权限内查询、办理、跳转。写操作先给可编辑提案,确认后执行、可一键撤销。
              </p>
            </div>
            <Composer onSend={send} busy={busy} autoFocus />
            <div className="mt-4 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  className="focus-ring rounded-full border border-line-2 bg-surface px-4 py-2 text-[14px] text-ink-2 transition-colors hover:border-line-3 hover:bg-surface-2"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <>
          <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto">
            <div className="mx-auto max-w-[880px] px-4 py-8">
              <div className="space-y-7">
                {messages.map((m) =>
                  m.role === 'user' ? (
                    <UserTurn key={m.id} text={m.text} />
                  ) : (
                    <AssistantTurn
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
              <div ref={endRef} />
            </div>
          </div>
          <div className="px-4 pb-5">
            <div className="mx-auto max-w-[880px]">
              <Composer onSend={send} busy={busy} />
              <p className="mt-2 text-center text-[13.5px] text-ink-mute">
                助手在权限闸门内操作,工具调用与写操作均经审计、可一键撤销 · AI 可能出错,请核对
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ─────────────────────────── 输入框(GPT/Claude 风格)───────────────────────────

function Composer({
  onSend,
  busy,
  autoFocus,
}: {
  onSend: (s: string) => void
  busy: boolean
  autoFocus?: boolean
}) {
  const [value, setValue] = useState('')
  const ref = useRef<HTMLTextAreaElement>(null)

  const grow = useCallback(() => {
    const el = ref.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`
  }, [])

  useLayoutEffect(grow, [value, grow])

  const submit = () => {
    const t = value.trim()
    if (!t || busy) return
    onSend(t)
    setValue('')
  }

  return (
    <div className="rounded-[26px] border border-line-2 bg-surface px-3.5 pt-3 pb-2.5 shadow-sm transition-colors focus-within:border-line-3 focus-within:shadow-md">
      <textarea
        ref={ref}
        value={value}
        autoFocus={autoFocus}
        rows={1}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            submit()
          }
        }}
        placeholder="给助手下达任务…"
        className="block max-h-[200px] w-full resize-none bg-transparent px-1.5 text-[16.5px] leading-7 text-ink outline-none placeholder:text-ink-mute"
      />
      <div className="mt-1.5 flex items-center justify-between pl-1.5">
        <span className="text-[13.5px] text-ink-mute">Enter 发送 · Shift+Enter 换行</span>
        <button
          onClick={submit}
          disabled={busy || !value.trim()}
          aria-label="发送"
          className="focus-ring grid h-9 w-9 place-items-center rounded-full bg-ink text-white transition-colors hover:bg-ink-2 disabled:bg-line-3 disabled:text-white"
        >
          {busy ? <Loader2 className="h-[18px] w-[18px] animate-spin" /> : <ArrowUp className="h-[18px] w-[18px]" />}
        </button>
      </div>
    </div>
  )
}

// ─────────────────────────── 消息 ───────────────────────────

function UserTurn({ text }: { text: string }) {
  return (
    <div className="flex justify-end">
      <div className="max-w-[78%] whitespace-pre-wrap rounded-3xl bg-surface-2 px-5 py-3 text-[16.5px] leading-7 text-ink">
        {text}
      </div>
    </div>
  )
}

interface AssistantTurnProps {
  msg: Extract<ChatMessage, { role: 'assistant' }>
  onConfirm: (p: ProposalState) => void
  onCancel: (p: ProposalState) => void
  onUndo: (p: ProposalState) => void
  onEdit: (p: ProposalState, key: string, value: unknown) => void
}

function AssistantTurn({ msg, onConfirm, onCancel, onUndo, onEdit }: AssistantTurnProps) {
  return (
    <div className="flex gap-3.5">
      <div className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-full bg-accent/10 text-accent">
        <Sparkles className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1 space-y-3">
        {msg.pending ? (
          <Thinking />
        ) : (
          <>
            {msg.blocked && (
              <div className="inline-flex items-center gap-1.5 rounded-full bg-crit/10 px-2.5 py-1 text-[13px] font-medium text-crit">
                <X className="h-3 w-3" /> 已被安全网关拦截
              </div>
            )}
            {msg.text && <Markdown>{msg.text}</Markdown>}
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

function Thinking() {
  return (
    <div className="flex items-center gap-1.5 py-1">
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-ink-mute [animation-delay:-0.3s]" />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-ink-mute [animation-delay:-0.15s]" />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-ink-mute" />
    </div>
  )
}

function Trace({ steps }: { steps: AssistantStep[] }) {
  const [open, setOpen] = useState(false)
  return (
    <div>
      <button
        onClick={() => setOpen((v) => !v)}
        className="focus-ring inline-flex items-center gap-1 rounded-md px-1 text-[13px] text-ink-mute transition-colors hover:text-ink-3"
      >
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? '' : '-rotate-90'}`} />
        执行过程 · {steps.length} 步
      </button>
      {open && (
        <div className="mt-1.5 space-y-1 border-l border-line pl-3">
          {steps.map((s, i) => (
            <div key={i} className="flex items-start gap-2 text-[13.5px]">
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

// ─────────────────────────── 写操作:可编辑提案卡片 ───────────────────────────

const RISK_DOT: Record<string, string> = {
  high: 'bg-crit',
  normal: 'bg-med',
  read_only: 'bg-ok',
}

interface ProposalCardProps {
  p: ProposalState
  onConfirm: () => void
  onCancel: () => void
  onUndo: () => void
  onEdit: (key: string, value: unknown) => void
}

function ProposalCard({ p, onConfirm, onCancel, onUndo, onEdit }: ProposalCardProps) {
  const editing = p.status === 'editing'
  const entries = Object.entries(p.editedArgs)
  const done = p.status === 'done' || p.status === 'undoing' || p.status === 'undone'

  return (
    <div className="space-y-3 rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className={`h-2 w-2 shrink-0 rounded-full ${RISK_DOT[p.action.risk] ?? 'bg-med'}`} />
          <span className="truncate text-[15px] font-medium text-ink">{p.action.label}</span>
        </div>
        <code className="shrink-0 text-[12px] text-ink-mute">{p.action.tool}</code>
      </div>

      {p.action.note && editing && (
        <p className="text-[13.5px] leading-snug text-ink-3">{p.action.note}</p>
      )}

      {entries.length > 0 && (
        <div className="space-y-2">
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

      {done && p.resultSummary && (
        <div className="rounded-lg bg-surface-2 px-3 py-2 text-[13.5px] leading-snug text-ink-2">
          {p.resultSummary}
        </div>
      )}

      <div className="flex items-center gap-2">
        {editing && (
          <>
            <button
              onClick={onConfirm}
              className="focus-ring rounded-lg bg-ink px-3.5 py-2 text-[14px] font-medium text-white transition-colors hover:bg-ink-2"
            >
              确认执行
            </button>
            <button
              onClick={onCancel}
              className="focus-ring rounded-lg px-3.5 py-2 text-[14px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink-2"
            >
              取消
            </button>
          </>
        )}
        {p.status === 'confirming' && (
          <span className="flex items-center gap-1.5 text-[13.5px] text-ink-3">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> 执行中…
          </span>
        )}
        {p.status === 'cancelled' && <span className="text-[13.5px] text-ink-mute">已取消</span>}
        {p.status === 'done' && p.reversible && p.actionId && (
          <button
            onClick={onUndo}
            className="focus-ring inline-flex items-center gap-1 rounded-lg border border-line-2 px-3.5 py-2 text-[14px] text-ink-2 transition-colors hover:border-line-3 hover:bg-surface-2"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            撤销{p.undoPreview ? `(${p.undoPreview})` : ''}
          </button>
        )}
        {p.status === 'done' && !(p.reversible && p.actionId) && (
          <span className="inline-flex items-center gap-1 text-[13.5px] text-ok">
            <Check className="h-3.5 w-3.5" /> 已执行
          </span>
        )}
        {p.status === 'undoing' && (
          <span className="flex items-center gap-1.5 text-[13.5px] text-ink-3">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> 撤销中…
          </span>
        )}
        {p.status === 'undone' && (
          <span className="inline-flex items-center gap-1 text-[13.5px] text-ink-mute">
            <RotateCcw className="h-3.5 w-3.5" /> 已撤销
          </span>
        )}
      </div>
    </div>
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
      <label className="w-32 shrink-0 truncate text-[14px] text-ink-3">{name}</label>
      {typeof value === 'boolean' ? (
        <input
          type="checkbox"
          checked={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
          className="h-[18px] w-[18px] accent-accent disabled:opacity-60"
        />
      ) : typeof value === 'number' ? (
        <input
          type="number"
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.valueAsNumber)}
          className="focus-ring h-9 w-full rounded-lg border border-line-2 bg-surface px-3 text-[14px] text-ink disabled:opacity-60"
        />
      ) : (
        <input
          type="text"
          value={String(value ?? '')}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          className="focus-ring h-9 w-full rounded-lg border border-line-2 bg-surface px-3 text-[14px] text-ink disabled:opacity-60"
        />
      )}
    </div>
  )
}
