import { useCallback, useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { Sparkles } from 'lucide-react'
import { toast } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import { t, useTranslation } from '@/lib/i18n'
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

// 起步意图(空态建议)—— 覆盖查/办/跳,克制不堆砌。在调用时解析当前语言(故为函数)。
const suggestions = (): string[] => [
  t('assistant.suggest.overview'),
  t('assistant.suggest.events'),
  t('assistant.suggest.approvals'),
  t('assistant.suggest.gateway'),
]

// 能力速记(空态副标题,克制不啰嗦)。
const caps = (): string[] => [
  t('assistant.cap.query'),
  t('assistant.cap.handle'),
  t('assistant.cap.navigate'),
  t('assistant.cap.settings'),
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

function toApprovalState(r: ApprovalRequest): ApprovalState {
  return { id: newId(), request: r, status: 'idle' }
}

export function AssistantPage() {
  const { t } = useTranslation()
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

  // 每会话一个 AbortController(M25):停止按钮/网络挂起时用户可主动中止当前会话的流。
  // 键为会话 id——切会话后各自的流互不干扰;组件卸载**不**中止(后台续写 store 是有意设计)。
  const aborters = useRef(new Map<string, AbortController>())

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
        toast.success(t('assistant.approval.toast.filed'), {
          description: t('assistant.approval.toast.filed_desc'),
        })
      } catch (e) {
        patchApproval(a.id, { status: 'failed' })
        toast.error(t('assistant.approval.toast.failed'), { description: (e as Error).message })
      }
    },
    [patchApproval, activeId],
  )

  const runDirective = useCallback(
    (d: UiDirective) => {
      if (d.tool === 'filter_events') {
        navigate('events')
        toast.success(t('assistant.nav.events'))
        return
      }
      if (d.tool === 'open_settings_panel') {
        navigate('settings')
        toast.success(t('assistant.nav.settings'))
        return
      }
      const feat = PAGE_TO_FEATURE[String(d.args.page ?? '')]
      if (feat) {
        navigate(feat)
        toast.success(t('assistant.nav.opened', { label: d.label }))
      }
    },
    [navigate, t],
  )

  // 流式更新:把某条 SSE 事件并入会话 cid 里 id=aid 的助手消息(按捕获的 cid 定向,切换会话不串)。
  const applyEvent = useCallback(
    (cid: string, aid: string, ev: StreamEvent) => {
      if (ev.type === 'ui') {
        if (mounted.current) runDirective(ev)
        return
      }
      if (ev.type === 'done' && ev.compressed) {
        toast(t('assistant.compress.title'), {
          description: t('assistant.compress.desc'),
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
    [runDirective, setMessagesOf, t],
  )

  const send = useCallback(
    async (raw: string) => {
      const text = raw.trim()
      if (!text || busy) return
      // 模型未配置:不发,提示并打开设置(有权配则可立即填,无权配则提示找管理员)。
      if (!modelReady) {
        toast.error(t('assistant.model.unconfigured'), {
          description: canConfigure
            ? t('assistant.model.unconfigured.configure')
            : t('assistant.model.unconfigured.contact'),
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
      const ac = new AbortController()
      aborters.current.set(cid, ac)
      try {
        await sendChatStream(text, cid, (ev) => applyEvent(cid, aid, ev), ac.signal)
      } catch (e) {
        // M25:错误**追加**在已流出内容之后,绝不整体替换——流到一半断线时已有的回答不丢。
        // 用户主动停止(abort)不是错误:已有内容原样保留;一字未出则标记「已停止」。
        const aborted = ac.signal.aborted
        setMessagesOf(cid, (m) =>
          m.map((x) => {
            if (x.id !== aid || x.role !== 'assistant') return x
            if (aborted) {
              return { ...x, pending: false, streaming: false, text: x.text || t('assistant.turn.stopped') }
            }
            const errText = t('assistant.turn.error', { msg: (e as Error).message })
            return {
              ...x,
              pending: false,
              streaming: false,
              text: x.text ? `${x.text}\n\n${errText}` : errText,
            }
          }),
        )
      } finally {
        aborters.current.delete(cid)
        // 收尾:无论如何把流式态落定(busy 由它派生)。即便组件已卸载,写的是模块 store,回答不丢。
        setMessagesOf(cid, (m) =>
          m.map((x) =>
            x.id === aid && x.role === 'assistant' ? { ...x, pending: false, streaming: false } : x,
          ),
        )
      }
    },
    [busy, activeId, applyEvent, setMessagesOf, modelReady, canConfigure, t],
  )

  // 停止当前会话的流式生成(M25)。abort 触发上方 catch:内容保留、streaming 落定、busy 解锁。
  const stopStreaming = useCallback(() => {
    aborters.current.get(activeId)?.abort()
  }, [activeId])

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
          toast.success(t('assistant.toast.executed'), { description: r.summary })
        } else {
          patchProposal(p.id, { status: 'editing' })
          toast.error(t('assistant.toast.execute_failed'), { description: r.summary })
        }
      } catch (e) {
        patchProposal(p.id, { status: 'editing' })
        toast.error((e as Error).message)
      }
    },
    [patchProposal, activeId, t],
  )

  const undo = useCallback(
    async (p: ProposalState) => {
      if (!p.actionId) return
      patchProposal(p.id, { status: 'undoing' })
      try {
        const r = await undoAction(p.actionId, activeId)
        if (r.ok) {
          patchProposal(p.id, { status: 'undone', resultSummary: r.summary })
          toast.success(t('assistant.toast.undone'), { description: r.summary })
        } else {
          patchProposal(p.id, { status: 'done' })
          toast.error(t('assistant.toast.undo_failed'), { description: r.summary })
        }
      } catch (e) {
        patchProposal(p.id, { status: 'done' })
        toast.error((e as Error).message)
      }
    },
    [patchProposal, activeId, t],
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
                  {t('assistant.hero.title')}
                </h1>
                <div className="flex flex-wrap items-center justify-center gap-x-2.5 gap-y-1 text-[15px] text-ink-3">
                  {caps().map((c, i) => (
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
                  onStop={stopStreaming}
                  busy={busy}
                  autoFocus
                  modelReady={modelReady}
                  canConfigure={canConfigure}
                  onOpenSettings={() => setSettingsOpen(true)}
                />
              </motion.div>
              <div className="mt-4 flex flex-wrap justify-center gap-2">
                {suggestions().map((s, i) => (
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
                  onStop={stopStreaming}
                  busy={busy}
                  modelReady={modelReady}
                  canConfigure={canConfigure}
                  onOpenSettings={() => setSettingsOpen(true)}
                />
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
