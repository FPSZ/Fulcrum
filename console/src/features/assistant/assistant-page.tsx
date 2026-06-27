import { useCallback, useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { Sparkles } from 'lucide-react'
import { toast } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import { useMediaQuery } from '@/lib/use-media-query'
import { useNavigateFeature } from '@/lib/nav'
import {
  type ApprovalRequest,
  type ApprovalState,
  EASE,
  PAGE_TO_FEATURE,
  type ProposalState,
  type ProposedAction,
  type StreamEvent,
  type UiDirective,
} from './data'
import {
  confirmAction,
  requestApproval,
  resetAssistant,
  sendChatStream,
  undoAction,
  useModelConfig,
} from './use-assistant'
import { useConversations } from './use-conversations'
import { ConversationSidebar } from './conversation-sidebar'
import { Composer } from './composer'
import { ModelSettingsModal } from './model-settings-modal'
import { AssistantTurn, UserTurn } from './message-turn'

// 起步意图(空态建议)—— 覆盖查/办/跳,克制不堆砌。
const SUGGESTIONS = [
  '看一下安全总览',
  '最近有哪些被拦截的事件?',
  '列出待审批的账号',
  '把上游网关名称改一下',
]

// 能力速记(空态副标题,克制不啰嗦)。
const CAPS = ['数据查询', '业务办理', '页面跳转', '更改设置']

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
                <p className="mt-2 text-center text-[13.5px] text-ink-mute">AI 可能出错,请核对结果</p>
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
