import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { useQueryClient } from '@tanstack/react-query'
import {
  ArrowUp,
  Check,
  ChevronDown,
  Loader2,
  Lock,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  RotateCcw,
  Send,
  Settings2,
  ShieldAlert,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react'
import { toast } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useAuth } from '@/lib/auth'
import { useMediaQuery } from '@/lib/use-media-query'
import { useNavigateFeature } from '@/lib/nav'
import {
  type ApprovalRequest,
  type ApprovalState,
  type AssistantStep,
  type ChatMessage,
  type ModelConfig,
  type ModelConfigUpdate,
  type ModelProtocol,
  type ModelTestResult,
  PAGE_TO_FEATURE,
  type ProposalState,
  type ProposedAction,
  type StreamEvent,
  type UiDirective,
} from './data'
import { Markdown } from './markdown'
import {
  confirmAction,
  requestApproval,
  resetAssistant,
  saveModelConfig,
  sendChatStream,
  testModelConfig,
  undoAction,
  useModelConfig,
} from './use-assistant'
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

function toApprovalState(r: ApprovalRequest): ApprovalState {
  return { id: newId(), request: r, status: 'idle' }
}

export function AssistantPage() {
  const navigate = useNavigateFeature()
  const { has } = useAuth()
  const canConfigure = has('ai.configure') // 仅超管/系统管理员(或被显式授权角色)可改模型接入
  // 模型接入配置:未就绪 → 设置按钮呼吸灯 + 发消息前置拦。
  const { data: modelCfg } = useModelConfig()
  const modelReady = modelCfg ? modelCfg.ready : true // 加载中先不拦(后端兜底)
  const [settingsOpen, setSettingsOpen] = useState(false)
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

  const scrollRef = useRef<HTMLDivElement>(null)
  const endRef = useRef<HTMLDivElement>(null)
  // 组件挂载态:卸载后流式仍在后台写 store(回答不丢),但导航类指令不再触发(别把已离开的用户拽走)。
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  // busy 由「当前会话是否有正在流式的回答」派生。状态在模块级 store,切页/回来都准确,
  // 后台仍在流的会话不会因组件重挂而误判为空闲。
  const busy = messages.some((m) => m.role === 'assistant' && m.streaming)

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

  const patchApproval = useCallback(
    (apprId: string, patch: Partial<ApprovalState>) => {
      setMessagesOf(activeId, (ms) =>
        ms.map((m) =>
          m.role === 'assistant'
            ? {
                ...m,
                approvals: (m.approvals ?? []).map((a) =>
                  a.id === apprId ? { ...a, ...patch } : a,
                ),
              }
            : m,
        ),
      )
    },
    [activeId, setMessagesOf],
  )

  // 发起审批申请:带上操作员自己填的审批理由,落一条真·待审批工单(进实时事件·待审批)。
  const fileApproval = useCallback(
    async (a: ApprovalState, reason: string) => {
      patchApproval(a.id, { status: 'filing' })
      try {
        await requestApproval({ ...a.request, reason }, activeId)
        patchApproval(a.id, { status: 'filed' })
        toast.success('已发起审批申请', {
          description: '已进入「实时事件 · 待审批」,管理员将在那里处理。',
        })
      } catch (e) {
        patchApproval(a.id, { status: 'failed' })
        toast.error('发起失败', { description: (e as Error).message })
      }
    },
    [patchApproval, activeId],
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
        if (mounted.current) runDirective(ev)
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
          if (ev.type === 'approval')
            return {
              ...x,
              pending: false,
              approvals: [...(x.approvals ?? []), toApprovalState(ev)],
            }
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
      // 模型未配置:不发,提示并打开设置(有权配则可立即填,无权配则提示找管理员)。
      if (!modelReady) {
        toast.error('模型尚未配置', {
          description: canConfigure
            ? '请先在设置里配置模型协议、端点与密钥。'
            : '请联系管理员配置 AI 模型接入后再使用。',
        })
        if (canConfigure) setSettingsOpen(true)
        return
      }
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
          approvals: [],
        },
      ])
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
        // 收尾:无论如何把流式态落定(busy 由它派生)。即便组件已卸载,写的是模块 store,回答不丢。
        setMessagesOf(cid, (m) =>
          m.map((x) =>
            x.id === aid && x.role === 'assistant' ? { ...x, pending: false, streaming: false } : x,
          ),
        )
      }
    },
    [busy, activeId, applyEvent, setMessagesOf, modelReady, canConfigure],
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
        {/* 切会话即刻换内容:不套 AnimatePresence mode="wait"(那会先等旧态退场 0.25s 才挂新态,
            从空态点历史会话时表现为「点了没反应」)。各分支自带挂载淡入,key 变即瞬时替换。 */}
        {empty ? (
          <motion.div
            key="hero"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
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
                <Composer
                  onSend={send}
                  busy={busy}
                  autoFocus
                  modelReady={modelReady}
                  canConfigure={canConfigure}
                  onOpenSettings={() => setSettingsOpen(true)}
                />
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
                          onFileApproval={fileApproval}
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
                <Composer
                  onSend={send}
                  busy={busy}
                  modelReady={modelReady}
                  canConfigure={canConfigure}
                  onOpenSettings={() => setSettingsOpen(true)}
                />
                <p className="mt-2 text-center text-[13.5px] text-ink-mute">
                  AI 可能出错,请核对结果
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </div>
      <AnimatePresence>
        {settingsOpen && (
          <ModelSettingsModal
            cfg={modelCfg}
            canConfigure={canConfigure}
            onClose={() => setSettingsOpen(false)}
          />
        )}
      </AnimatePresence>
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
  modelReady,
  canConfigure,
  onOpenSettings,
}: {
  onSend: (s: string) => void
  busy: boolean
  autoFocus?: boolean
  modelReady: boolean
  canConfigure: boolean
  onOpenSettings: () => void
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
        <div className="flex items-center gap-2.5">
          <SettingsButton
            ready={modelReady}
            canConfigure={canConfigure}
            onClick={onOpenSettings}
          />
          <span className="text-[13px] text-ink-mute">
            {modelReady
              ? 'Enter 发送 · Shift+Enter 换行'
              : canConfigure
                ? '模型未配置 · 点左侧设置'
                : '模型未配置 · 请联系管理员'}
          </span>
        </div>
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

// ─────────────────────────── 模型设置:输入框左侧入口 + 配置弹窗 ───────────────────────────

/** 设置齿轮:有「AI 模型配置」权限才可点;未配置时蓝色呼吸灯闪烁。无权限 → 灰、禁用、不可点。 */
function SettingsButton({
  ready,
  canConfigure,
  onClick,
}: {
  ready: boolean
  canConfigure: boolean
  onClick: () => void
}) {
  // 无权限:灰色禁用,不闪呼吸灯,点不动(提示找管理员)。
  if (!canConfigure) {
    return (
      <button
        type="button"
        disabled
        aria-label="模型设置(需权限)"
        title="配置 AI 模型需「AI 模型配置」权限,请联系管理员"
        className="grid h-8 w-8 cursor-not-allowed place-items-center rounded-full text-ink-mute/40"
      >
        <Settings2 className="h-[18px] w-[18px]" strokeWidth={1.9} />
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="模型设置"
      title={ready ? '模型设置' : '模型未配置 —— 点击配置'}
      className={cn(
        'focus-ring relative grid h-8 w-8 place-items-center rounded-full transition-colors',
        ready ? 'text-ink-mute hover:bg-surface-2 hover:text-ink-2' : 'text-accent hover:bg-accent/10',
      )}
    >
      {!ready && (
        <>
          <span className="pointer-events-none absolute inset-0 animate-ping rounded-full bg-accent/30" />
          <span className="pointer-events-none absolute inset-0 animate-pulse rounded-full ring-2 ring-accent/50" />
        </>
      )}
      <Settings2 className="relative h-[18px] w-[18px]" strokeWidth={1.9} />
    </button>
  )
}

// 协议元信息(表单提示)与一键预设(本地私有化优先)。
const PROTO_META: Record<
  ModelProtocol,
  { name: string; hint: string; endpointPh: string; modelPh: string }
> = {
  openai: {
    name: 'OpenAI 兼容',
    hint: '覆盖 OpenAI / DeepSeek / Kimi / MiMo,以及本地 vLLM / LM Studio / llama.cpp / Ollama 的 /v1 端点',
    endpointPh: 'https://api.openai.com/v1 或 http://127.0.0.1:1234/v1',
    modelPh: 'gpt-4o-mini / deepseek-chat / qwen2.5',
  },
  ollama: {
    name: 'Ollama 原生',
    hint: '本地私有化最常见,通常免密钥',
    endpointPh: 'http://127.0.0.1:11434',
    modelPh: 'qwen2.5 / llama3.1 / deepseek-r1',
  },
  anthropic: {
    name: 'Anthropic',
    hint: 'Claude /v1/messages',
    endpointPh: 'https://api.anthropic.com',
    modelPh: 'claude-3-5-sonnet-latest',
  },
}

const PRESETS: { label: string; protocol: ModelProtocol; endpoint: string; model: string }[] = [
  { label: 'Ollama 本地', protocol: 'ollama', endpoint: 'http://127.0.0.1:11434', model: 'qwen2.5' },
  {
    label: 'LM Studio 本地',
    protocol: 'openai',
    endpoint: 'http://127.0.0.1:1234/v1',
    model: 'local-model',
  },
  { label: 'vLLM 本地', protocol: 'openai', endpoint: 'http://127.0.0.1:8000/v1', model: '' },
  { label: 'OpenAI', protocol: 'openai', endpoint: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  {
    label: 'DeepSeek',
    protocol: 'openai',
    endpoint: 'https://api.deepseek.com/v1',
    model: 'deepseek-chat',
  },
  {
    label: 'Anthropic',
    protocol: 'anthropic',
    endpoint: 'https://api.anthropic.com',
    model: 'claude-3-5-sonnet-latest',
  },
]

function ModelSettingsModal({
  cfg,
  canConfigure,
  onClose,
}: {
  cfg: ModelConfig | undefined
  canConfigure: boolean
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [protocol, setProtocol] = useState<ModelProtocol>(cfg?.protocol ?? 'openai')
  const [endpoint, setEndpoint] = useState(cfg?.endpoint ?? '')
  const [model, setModel] = useState(cfg?.model ?? '')
  const [apiKey, setApiKey] = useState('') // 留空=保持原密钥;键入=设新值
  const [timeoutS, setTimeoutS] = useState(cfg?.timeout_seconds ?? 90)
  const [verifyTls, setVerifyTls] = useState(cfg?.verify_tls ?? true)
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<ModelTestResult | null>(null)
  const [saving, setSaving] = useState(false)

  // Esc 关闭。
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const meta = PROTO_META[protocol]
  const ro = !canConfigure
  const valid = endpoint.trim() !== '' && model.trim() !== ''

  const payload = (): ModelConfigUpdate => ({
    protocol,
    endpoint: endpoint.trim(),
    model: model.trim(),
    api_key: apiKey ? apiKey : undefined,
    timeout_seconds: timeoutS,
    verify_tls: verifyTls,
  })

  const applyPreset = (p: (typeof PRESETS)[number]) => {
    setProtocol(p.protocol)
    setEndpoint(p.endpoint)
    setModel(p.model)
    setResult(null)
  }

  const onTest = async () => {
    setTesting(true)
    setResult(null)
    try {
      setResult(await testModelConfig(payload()))
    } catch (e) {
      setResult({ ok: false, detail: (e as Error).message })
    } finally {
      setTesting(false)
    }
  }

  const onSave = async () => {
    setSaving(true)
    try {
      await saveModelConfig(payload())
      await qc.invalidateQueries({ queryKey: ['assistant', 'model-config'] })
      toast.success('已保存模型配置', { description: '热加载生效,现在可以开始对话了。' })
      onClose()
    } catch (e) {
      toast.error('保存失败', { description: (e as Error).message })
    } finally {
      setSaving(false)
    }
  }

  const inputCls =
    'focus-ring h-10 w-full rounded-lg border border-line-2 bg-surface px-3 text-[14px] text-ink placeholder:text-ink-mute disabled:opacity-60'

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.18 }}
      onClick={onClose}
      className="fixed inset-0 z-50 grid place-items-center bg-ink/40 p-4 backdrop-blur-sm"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.97, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.98, y: 6 }}
        transition={{ duration: 0.22, ease: EASE }}
        onClick={(e) => e.stopPropagation()}
        className="flex max-h-[88vh] w-full max-w-[560px] flex-col overflow-hidden rounded-2xl border border-line bg-surface shadow-xl"
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent/10 text-accent">
              <Settings2 className="h-[18px] w-[18px]" />
            </div>
            <h2 className="text-[16px] font-semibold text-ink">AI 模型接入</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭"
            className="focus-ring grid h-8 w-8 place-items-center rounded-lg text-ink-mute transition-colors hover:bg-surface-2 hover:text-ink-2"
          >
            <X className="h-[18px] w-[18px]" />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {ro && (
            <div className="flex items-start gap-2 rounded-lg bg-med/10 px-3 py-2.5 text-[13px] text-med">
              <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>你没有「AI 模型配置」权限,以下为只读。请联系超级管理员或系统管理员配置。</span>
            </div>
          )}

          <div>
            <Label>协议</Label>
            <div className="grid grid-cols-3 gap-2">
              {(Object.keys(PROTO_META) as ModelProtocol[]).map((p) => (
                <button
                  key={p}
                  type="button"
                  disabled={ro}
                  onClick={() => {
                    setProtocol(p)
                    setResult(null)
                  }}
                  className={cn(
                    'focus-ring rounded-lg border px-2 py-2 text-[13.5px] font-medium transition-colors disabled:opacity-60',
                    protocol === p
                      ? 'border-accent bg-accent/10 text-accent-ink'
                      : 'border-line-2 bg-surface text-ink-2 hover:border-line-3 hover:bg-surface-2',
                  )}
                >
                  {PROTO_META[p].name}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[12.5px] leading-snug text-ink-mute">{meta.hint}</p>
          </div>

          {!ro && (
            <div>
              <Label>快速预设</Label>
              <div className="flex flex-wrap gap-1.5">
                {PRESETS.map((p) => (
                  <button
                    key={p.label}
                    type="button"
                    onClick={() => applyPreset(p)}
                    className="focus-ring rounded-full border border-line-2 bg-surface px-2.5 py-1 text-[12.5px] text-ink-2 transition-colors hover:border-accent/40 hover:bg-accent/5 hover:text-accent-ink"
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div>
            <Label>端点 Endpoint</Label>
            <input
              value={endpoint}
              disabled={ro}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder={meta.endpointPh}
              className={cn(inputCls, 'font-mono text-[13px]')}
            />
          </div>

          <div>
            <Label>模型名 Model</Label>
            <input
              value={model}
              disabled={ro}
              onChange={(e) => setModel(e.target.value)}
              placeholder={meta.modelPh}
              className={inputCls}
            />
          </div>

          <div>
            <Label>API Key（本地模型可留空）</Label>
            <input
              type="password"
              value={apiKey}
              disabled={ro}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={
                cfg?.api_key_set ? `已配置 ${cfg.api_key_masked}(留空保持不变)` : '本地模型可留空'
              }
              autoComplete="off"
              className={cn(inputCls, 'font-mono text-[13px]')}
            />
          </div>

          <div className="flex items-center gap-4">
            <div className="flex-1">
              <Label>超时(秒)</Label>
              <input
                type="number"
                value={timeoutS}
                disabled={ro}
                min={1}
                max={600}
                onChange={(e) => setTimeoutS(e.target.valueAsNumber || 90)}
                className={inputCls}
              />
            </div>
            <label className="flex cursor-pointer items-center gap-2 pt-5 text-[13.5px] text-ink-2">
              <input
                type="checkbox"
                checked={verifyTls}
                disabled={ro}
                onChange={(e) => setVerifyTls(e.target.checked)}
                className="h-[16px] w-[16px] accent-accent disabled:opacity-60"
              />
              校验 TLS 证书
            </label>
          </div>

          {result && (
            <div
              className={cn(
                'flex items-start gap-2 rounded-lg px-3 py-2.5 text-[13px]',
                result.ok ? 'bg-ok/10 text-ok' : 'bg-crit/10 text-crit',
              )}
            >
              {result.ok ? (
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              ) : (
                <X className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              )}
              <span>
                {result.detail}
                {result.ok && result.latency_ms != null ? `(${result.latency_ms} ms)` : ''}
              </span>
            </div>
          )}
        </div>

        {!ro && (
          <div className="flex items-center justify-between gap-2 border-t border-line px-5 py-3.5">
            <button
              type="button"
              onClick={onTest}
              disabled={!valid || testing}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg border border-line-2 px-3.5 py-2 text-[14px] text-ink-2 transition-colors hover:border-line-3 hover:bg-surface-2 disabled:opacity-50"
            >
              {testing && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              测试连接
            </button>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onClose}
                className="focus-ring rounded-lg px-3.5 py-2 text-[14px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink-2"
              >
                取消
              </button>
              <motion.button
                type="button"
                whileTap={{ scale: 0.96 }}
                onClick={onSave}
                disabled={!valid || saving}
                className="focus-ring inline-flex items-center gap-1.5 rounded-lg bg-accent px-4 py-2 text-[14px] font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
              >
                {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                保存
              </motion.button>
            </div>
          </div>
        )}
      </motion.div>
    </motion.div>
  )
}

function Label({ children }: { children: ReactNode }) {
  return <div className="mb-1.5 text-[13px] font-medium text-ink-2">{children}</div>
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
  onFileApproval: (a: ApprovalState, reason: string) => void
}

function AssistantTurn({ msg, onConfirm, onCancel, onUndo, onEdit, onFileApproval }: AssistantTurnProps) {
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
            {(msg.approvals ?? []).map((a) => (
              <ApprovalCard key={a.id} a={a} onFile={(reason) => onFileApproval(a, reason)} />
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
  high: 'bg-accent',
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
              className="focus-ring rounded-lg bg-accent px-3.5 py-2 text-[14px] font-medium text-white transition-colors hover:bg-accent-hover"
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

// ─────────────────────────── 待审批:发起申请卡片(复用提案卡外壳 + 审批理由框)──────────

/** 闸判「待审批」→ 当面卡片(与写提案卡同一套外壳):操作员填审批理由,点「发起」才落真工单。 */
function ApprovalCard({ a, onFile }: { a: ApprovalState; onFile: (reason: string) => void }) {
  const { request: r, status } = a
  const [reason, setReason] = useState('')
  const editing = status === 'idle' || status === 'failed'

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.985, y: 8 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.26, ease: EASE }}
      className="space-y-3 rounded-2xl border border-line bg-surface p-4 shadow-sm"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent/12 text-accent">
            <ShieldAlert className="h-4 w-4" />
          </span>
          <span className="truncate text-[15px] font-medium text-ink">{r.title}</span>
        </div>
        <span className="shrink-0 rounded-full bg-accent/10 px-2 py-0.5 text-[12px] font-medium text-accent-ink">
          需管理员审批
        </span>
      </div>

      {/* 触发依据:凭什么判待审(脱敏摘要,供操作员核对) */}
      {r.excerpt && (
        <div className="rounded-lg bg-surface-2 px-3 py-2 text-[13px] leading-snug text-ink-2">
          {r.excerpt}
        </div>
      )}

      {/* 审批理由:操作员自己填,随工单一并提交给管理员 */}
      <div>
        <div className="mb-1.5 text-[13px] font-medium text-ink-2">审批理由</div>
        <textarea
          value={reason}
          disabled={!editing}
          onChange={(e) => setReason(e.target.value)}
          rows={2}
          placeholder="说明为什么需要执行这一步,管理员据此审批…"
          className="focus-ring min-h-[60px] w-full resize-y rounded-lg border border-line-2 bg-surface px-3 py-2 text-[14px] leading-6 text-ink outline-none placeholder:text-ink-mute disabled:opacity-60"
        />
      </div>

      <div className="flex items-center gap-2">
        {editing && (
          <>
            <motion.button
              whileTap={{ scale: 0.95 }}
              onClick={() => onFile(reason.trim())}
              disabled={!reason.trim()}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-[14px] font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              {status === 'failed' ? '重试发起' : '发起审批申请'}
            </motion.button>
            <span className="text-[13px] text-ink-mute">不发起则不留工单</span>
          </>
        )}
        {status === 'filing' && (
          <span className="flex items-center gap-1.5 text-[13.5px] text-ink-3">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> 发起中…
          </span>
        )}
        {status === 'filed' && (
          <span className="inline-flex items-center gap-1.5 text-[13.5px] text-accent-ink">
            <Check className="h-3.5 w-3.5" /> 已进入待审批,管理员处理中
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
