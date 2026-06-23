import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  ArrowUp,
  Check,
  ChevronDown,
  Loader2,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  RotateCcw,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react'
import { toast } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useMediaQuery } from '@/lib/use-media-query'
import { useNavigateFeature } from '@/lib/nav'
import {
  type AssistantStep,
  type ChatMessage,
  PAGE_TO_FEATURE,
  type ProposalState,
  type ProposedAction,
  type StreamEvent,
  type UiDirective,
} from './data'
import { Markdown } from './markdown'
import { confirmAction, resetAssistant, sendChatStream, undoAction } from './use-assistant'
import { type Conversation, useConversations } from './use-conversations'

// 起步意图(空态建议)—— 覆盖查/办/跳,克制不堆砌。
const SUGGESTIONS = [
  '看一下安全总览',
  '最近有哪些被拦截的事件?',
  '列出待审批的账号',
  '把上游网关名称改一下',
]

// 能力速记(空态副标题,克制不啰嗦)。
const CAPS = ['数据查询', '业务办理', '页面跳转', '更改设置']

const EASE = [0.25, 1, 0.5, 1] as const

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
  // 多会话:每条会话 = 独立 session_id(后端记忆按它分桶)。切换会话即切上下文,各自延续。
  const {
    activeId,
    messages,
    history,
    setMessagesOf,
    newConversation,
    selectConversation,
    removeConversation,
  } = useConversations()

  const [busy, setBusy] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages])

  const patchProposal = useCallback(
    (propId: string, patch: Partial<ProposalState>) => {
      setMessagesOf(activeId, (ms) =>
        ms.map((m) =>
          m.role === 'assistant'
            ? { ...m, proposals: m.proposals.map((p) => (p.id === propId ? { ...p, ...patch } : p)) }
            : m,
        ),
      )
    },
    [activeId, setMessagesOf],
  )

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

  // 流式更新:把某条 SSE 事件并入会话 cid 里 id=aid 的助手消息(按捕获的 cid 定向,切换会话不串)。
  const applyEvent = useCallback(
    (cid: string, aid: string, ev: StreamEvent) => {
      if (ev.type === 'ui') {
        runDirective(ev)
        return
      }
      if (ev.type === 'done' && ev.compressed) {
        toast('已自动压缩较早的上下文', {
          description: '对话较长,枢衡已把更早的内容压成摘要以延续上下文。',
        })
      }
      setMessagesOf(cid, (ms) =>
        ms.map((x) => {
          if (x.id !== aid || x.role !== 'assistant') return x
          if (ev.type === 'delta') return { ...x, pending: false, text: x.text + ev.text }
          if (ev.type === 'step') return { ...x, pending: false, steps: [...x.steps, ev] }
          if (ev.type === 'proposal')
            return { ...x, pending: false, proposals: [...x.proposals, toProposalState(ev)] }
          if (ev.type === 'done')
            return {
              ...x,
              pending: false,
              streaming: false,
              blocked: ev.blocked,
              text: ev.reply || x.text,
            }
          return x
        }),
      )
    },
    [runDirective, setMessagesOf],
  )

  const send = useCallback(
    async (raw: string) => {
      const text = raw.trim()
      if (!text || busy) return
      const cid = activeId // 捕获当轮会话,流式回调按它写,期间切会话也不串
      const aid = newId()
      setMessagesOf(cid, (m) => [
        ...m,
        { id: newId(), role: 'user', text },
        {
          id: aid,
          role: 'assistant',
          text: '',
          pending: true,
          streaming: true,
          blocked: false,
          steps: [],
          proposals: [],
        },
      ])
      setBusy(true)
      try {
        await sendChatStream(text, cid, (ev) => applyEvent(cid, aid, ev))
      } catch (e) {
        setMessagesOf(cid, (m) =>
          m.map((x) =>
            x.id === aid && x.role === 'assistant'
              ? { ...x, pending: false, streaming: false, text: `出错:${(e as Error).message}` }
              : x,
          ),
        )
      } finally {
        setBusy(false)
        setMessagesOf(cid, (m) =>
          m.map((x) =>
            x.id === aid && x.role === 'assistant' ? { ...x, pending: false, streaming: false } : x,
          ),
        )
      }
    },
    [busy, activeId, applyEvent, setMessagesOf],
  )

  // 新建会话:开一条新草稿(空态)。旧会话记忆保留,侧栏点回去上下文还在。
  const startNew = useCallback(() => {
    if (busy) return
    newConversation()
  }, [busy, newConversation])

  // 删除会话:移出侧栏 + 清后端该会话的多轮记忆(释放磁盘)。
  const deleteConversation = useCallback(
    (id: string) => {
      removeConversation(id)
      void resetAssistant(id)
    },
    [removeConversation],
  )

  const confirm = useCallback(
    async (p: ProposalState) => {
      patchProposal(p.id, { status: 'confirming' })
      try {
        const r = await confirmAction(p.action.action_token, p.editedArgs, activeId)
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
    [patchProposal, activeId],
  )

  const undo = useCallback(
    async (p: ProposalState) => {
      if (!p.actionId) return
      patchProposal(p.id, { status: 'undoing' })
      try {
        const r = await undoAction(p.actionId, activeId)
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
    [patchProposal, activeId],
  )

  const empty = messages.length === 0

  // 会话侧栏折叠:窄屏(<1280)自动收起;用户手动切换后以手动为准。
  const sideNarrow = useMediaQuery('(max-width: 1280px)')
  const [sideManual, setSideManual] = useState<boolean | null>(null)
  const sideCollapsed = sideManual ?? sideNarrow
  const toggleSide = useCallback(() => setSideManual(() => !sideCollapsed), [sideCollapsed])

  return (
    <div className="flex min-h-0 flex-1 bg-canvas">
      <ConversationSidebar
        history={history}
        activeId={activeId}
        busy={busy}
        collapsed={sideCollapsed}
        onToggle={toggleSide}
        onNew={startNew}
        onSelect={selectConversation}
        onDelete={deleteConversation}
      />
      <div className="flex min-h-0 flex-1 flex-col">
        <AnimatePresence mode="wait" initial={false}>
        {empty ? (
          <motion.div
            key="hero"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25, ease: EASE }}
            className="flex min-h-0 flex-1 flex-col items-center justify-center px-4 pb-16"
          >
            <div className="w-full max-w-[768px]">
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, ease: EASE }}
                className="mb-7 flex flex-col items-center gap-3 text-center"
              >
                <div className="grid h-12 w-12 place-items-center rounded-2xl bg-accent/10 text-accent">
                  <Sparkles className="h-6 w-6" />
                </div>
                <h1 className="text-[28px] font-semibold tracking-tight text-ink">
                  需要我帮你做点什么?
                </h1>
                <div className="flex flex-wrap items-center justify-center gap-x-2.5 gap-y-1 text-[15px] text-ink-3">
                  {CAPS.map((c, i) => (
                    <span key={c} className="flex items-center gap-2.5">
                      {i > 0 && <span className="text-line-3">·</span>}
                      {c}
                    </span>
                  ))}
                </div>
              </motion.div>
              <motion.div
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, ease: EASE, delay: 0.05 }}
              >
                <Composer onSend={send} busy={busy} autoFocus />
              </motion.div>
              <div className="mt-4 flex flex-wrap justify-center gap-2">
                {SUGGESTIONS.map((s, i) => (
                  <motion.button
                    key={s}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, ease: EASE, delay: 0.12 + i * 0.05 }}
                    whileTap={{ scale: 0.96 }}
                    onClick={() => send(s)}
                    className="focus-ring rounded-full border border-line-2 bg-surface px-4 py-2 text-[14px] text-ink-2 transition-colors hover:border-line-3 hover:bg-surface-2"
                  >
                    {s}
                  </motion.button>
                ))}
              </div>
            </div>
          </motion.div>
        ) : (
          <motion.div
            key="chat"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.25, ease: EASE }}
            className="flex min-h-0 flex-1 flex-col"
          >
            <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto">
              <div className="mx-auto max-w-[768px] px-5 py-8">
                <div className="space-y-7">
                  {messages.map((m) => (
                    <motion.div
                      key={m.id}
                      layout="position"
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.28, ease: EASE }}
                    >
                      {m.role === 'user' ? (
                        <UserTurn text={m.text} />
                      ) : (
                        <AssistantTurn
                          msg={m}
                          onConfirm={confirm}
                          onCancel={(p) => patchProposal(p.id, { status: 'cancelled' })}
                          onUndo={undo}
                          onEdit={(p, k, v) =>
                            patchProposal(p.id, { editedArgs: { ...p.editedArgs, [k]: v } })
                          }
                        />
                      )}
                    </motion.div>
                  ))}
                </div>
                <div ref={endRef} />
              </div>
            </div>
            <div className="px-4 pb-5">
              <div className="mx-auto max-w-[768px]">
                <Composer onSend={send} busy={busy} />
                <p className="mt-2 text-center text-[13.5px] text-ink-mute">
                  助手在权限闸门内操作,工具调用与写操作均经审计、可一键撤销 · AI 可能出错,请核对
                </p>
              </div>
            </div>
          </motion.div>
        )}
        </AnimatePresence>
      </div>
    </div>
  )
}

// ─────────────────────────── 会话侧栏(Kimi 式:新建会话 + 历史)───────────────────────────

function ConversationSidebar({
  history,
  activeId,
  busy,
  collapsed,
  onToggle,
  onNew,
  onSelect,
  onDelete,
}: {
  history: Conversation[]
  activeId: string
  busy: boolean
  collapsed: boolean
  onToggle: () => void
  onNew: () => void
  onSelect: (id: string) => void
  onDelete: (id: string) => void
}) {
  return (
    <motion.aside
      animate={{ width: collapsed ? 56 : 264 }}
      transition={{ duration: 0.22, ease: EASE }}
      className="shrink-0 overflow-hidden border-r border-line bg-surface/50"
    >
      {collapsed ? (
        // 收起态:窄轨,只留「展开」+「新建会话」两个图标
        <div className="flex w-14 flex-col items-center gap-1.5 py-3.5">
          <button
            type="button"
            onClick={onToggle}
            aria-label="展开会话栏"
            className="focus-ring grid h-9 w-9 place-items-center rounded-[11px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink"
          >
            <PanelLeftOpen className="h-[18px] w-[18px]" strokeWidth={1.8} />
          </button>
          <button
            type="button"
            onClick={onNew}
            disabled={busy}
            aria-label="新建会话"
            className="focus-ring grid h-9 w-9 place-items-center rounded-[11px] border border-line-2 bg-surface text-ink transition-colors hover:bg-surface-2 disabled:opacity-50"
          >
            <Plus className="h-[18px] w-[18px]" strokeWidth={2} />
          </button>
        </div>
      ) : (
        <div className="flex h-full w-[264px] flex-col">
          <div className="flex items-center justify-between px-3.5 pb-1 pt-3">
            <span className="text-[13px] font-semibold text-ink-mute">会话</span>
            <button
              type="button"
              onClick={onToggle}
              aria-label="收起会话栏"
              className="focus-ring grid h-7 w-7 place-items-center rounded-md text-ink-mute transition-colors hover:bg-surface-2 hover:text-ink-2"
            >
              <PanelLeftClose className="h-4 w-4" strokeWidth={1.8} />
            </button>
          </div>
          <div className="px-3.5 pb-1 pt-1.5">
            <button
              type="button"
              onClick={onNew}
              disabled={busy}
              className="focus-ring flex w-full items-center gap-2 rounded-xl border border-line-2 bg-surface px-3.5 py-3 text-[14.5px] font-medium text-ink transition-colors hover:border-line-3 hover:bg-surface-2 disabled:opacity-50"
            >
              <Plus className="h-[18px] w-[18px]" strokeWidth={2} /> 新建会话
            </button>
          </div>
          <div className="px-4 pb-2 pt-2.5 text-[12.5px] font-semibold tracking-wide text-ink-mute">
            历史会话
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-2.5 pb-3">
        {history.length === 0 ? (
          <p className="px-2 py-8 text-center text-[13px] leading-relaxed text-ink-mute">
            暂无历史会话
            <br />
            开始对话即在此留存
          </p>
        ) : (
          history.map((c) => {
            const active = c.id === activeId
            return (
              <div
                key={c.id}
                className={cn(
                  'group flex items-center gap-1 rounded-lg px-3 py-2.5 transition-colors',
                  active ? 'bg-accent/12' : 'hover:bg-surface-2',
                )}
              >
                <button
                  type="button"
                  onClick={() => onSelect(c.id)}
                  className="min-w-0 flex-1 text-left"
                >
                  <span
                    className={cn(
                      'block truncate text-[14px]',
                      active ? 'font-medium text-accent-ink' : 'text-ink-2',
                    )}
                  >
                    {c.title || '新对话'}
                  </span>
                </button>
                <button
                  type="button"
                  aria-label="删除会话"
                  onClick={() => onDelete(c.id)}
                  className="focus-ring grid h-6 w-6 shrink-0 place-items-center rounded-md text-ink-mute opacity-0 transition-opacity hover:bg-line/40 hover:text-ink-2 group-hover:opacity-100"
                >
                  <Trash2 className="h-3.5 w-3.5" strokeWidth={1.8} />
                </button>
              </div>
            )
          })
        )}
          </div>
        </div>
      )}
    </motion.aside>
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
    // Kimi 比例:圆角 ~18px、内容区高、底部一条工具栏(发送贴右),整体约 140px 高。
    <div className="rounded-[18px] border border-line-2 bg-surface px-4 pb-3 pt-3.5 shadow-sm transition-all focus-within:border-line-3 focus-within:shadow-md">
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
        className="block min-h-[60px] max-h-[200px] w-full resize-none bg-transparent px-1 text-[16px] leading-7 text-ink outline-none placeholder:text-ink-mute"
      />
      <div className="mt-1 flex items-center justify-between px-0.5">
        <span className="text-[13px] text-ink-mute">Enter 发送 · Shift+Enter 换行</span>
        <motion.button
          onClick={submit}
          disabled={busy || !value.trim()}
          aria-label="发送"
          whileTap={{ scale: 0.88 }}
          transition={{ duration: 0.12 }}
          className="focus-ring grid h-9 w-9 place-items-center rounded-full bg-ink text-white transition-colors hover:bg-ink-2 disabled:bg-line-3 disabled:text-white"
        >
          {busy ? (
            <Loader2 className="h-[18px] w-[18px] animate-spin" />
          ) : (
            <ArrowUp className="h-[18px] w-[18px]" />
          )}
        </motion.button>
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
            {msg.text && (
              <div className="relative">
                <Markdown>{msg.text}</Markdown>
                {msg.streaming && (
                  <span className="ml-0.5 inline-block h-[15px] w-[2px] translate-y-[2px] animate-pulse bg-ink-2 align-middle" />
                )}
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
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: EASE }}
            className="overflow-hidden"
          >
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
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ─────────────────────────── 写操作:可编辑提案卡片(VSCode 式差异)───────────────────────────

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
  const before = p.action.before ?? {}
  const done = p.status === 'done' || p.status === 'undoing' || p.status === 'undone'

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.985, y: 8 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.26, ease: EASE }}
      className="space-y-3 rounded-2xl border border-line bg-surface p-4 shadow-sm"
    >
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
              hasBefore={k in before}
              before={before[k]}
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
            <motion.button
              whileTap={{ scale: 0.95 }}
              onClick={onConfirm}
              className="focus-ring rounded-lg bg-ink px-3.5 py-2 text-[14px] font-medium text-white transition-colors hover:bg-ink-2"
            >
              确认执行
            </motion.button>
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
          <motion.button
            whileTap={{ scale: 0.95 }}
            onClick={onUndo}
            className="focus-ring inline-flex items-center gap-1 rounded-lg border border-line-2 px-3.5 py-2 text-[14px] text-ink-2 transition-colors hover:border-line-3 hover:bg-surface-2"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            撤销{p.undoPreview ? `(${p.undoPreview})` : ''}
          </motion.button>
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
    </motion.div>
  )
}

function asText(v: unknown): string {
  if (typeof v === 'boolean') return v ? '是' : '否'
  return String(v ?? '')
}

function FieldRow({
  name,
  value,
  before,
  hasBefore,
  disabled,
  onChange,
}: {
  name: string
  value: unknown
  before: unknown
  hasBefore: boolean
  disabled: boolean
  onChange: (v: unknown) => void
}) {
  const changed = hasBefore && asText(before) !== asText(value)

  // 改动字段:VSCode 式 before→after(红删/绿增),新值可编辑。
  if (changed) {
    return (
      <div className="overflow-hidden rounded-lg border border-line font-mono text-[13.5px]">
        <div className="flex gap-2 bg-crit/8 px-3 py-1.5 text-crit">
          <span className="select-none opacity-60">−</span>
          <span className="shrink-0 opacity-80">{name}:</span>
          <span className="min-w-0 break-all line-through opacity-90">{asText(before)}</span>
        </div>
        <div className="flex items-center gap-2 bg-ok/12 px-3 py-1.5">
          <span className="select-none text-ok opacity-70">+</span>
          <span className="shrink-0 text-ink-3">{name}:</span>
          {typeof value === 'boolean' ? (
            <input
              type="checkbox"
              checked={value}
              disabled={disabled}
              onChange={(e) => onChange(e.target.checked)}
              className="h-[16px] w-[16px] accent-accent disabled:opacity-60"
            />
          ) : (
            <input
              type={typeof value === 'number' ? 'number' : 'text'}
              value={typeof value === 'number' ? value : String(value ?? '')}
              disabled={disabled}
              onChange={(e) =>
                onChange(typeof value === 'number' ? e.target.valueAsNumber : e.target.value)
              }
              className="focus-ring min-w-0 flex-1 rounded border border-ok/30 bg-surface px-2 py-0.5 text-ink disabled:opacity-60"
            />
          )}
        </div>
      </div>
    )
  }

  // 普通字段:紧凑可编辑行。
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
