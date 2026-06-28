import { useSyncExternalStore } from 'react'
import type { ChatMessage } from './data'

/** 一条会话:id 即后端 session_id(多轮记忆按它分桶);标题取首条用户消息。 */
export interface Conversation {
  id: string
  title: string
  messages: ChatMessage[]
  updatedAt: number
}

const LS_KEY = 'fulcrum.assistant.conversations.v1'

/** 生成会话 id(与后端约定的 assistant:web: 前缀一致)。 */
export function makeSessionId(): string {
  const rand =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().slice(0, 8)
      : Math.random().toString(36).slice(2, 10)
  return `assistant:web:${rand}`
}

// 标题取首条用户消息;无则留空,由 UI 层按当前语言回退展示「新对话」(不冻结语言)。
function deriveTitle(messages: ChatMessage[]): string {
  const firstUser = messages.find((m) => m.role === 'user')
  const txt = (firstUser?.text ?? '').trim().replace(/\s+/g, ' ')
  return txt ? (txt.length > 22 ? `${txt.slice(0, 22)}…` : txt) : ''
}

function loadList(): Conversation[] {
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as { conversations?: Conversation[] }
    return Array.isArray(parsed.conversations) ? parsed.conversations : []
  } catch {
    return []
  }
}

// ─────────────────────────── 模块级单例存储 ───────────────────────────
// 关键:状态住在组件之外。这样切换页面 / 卸载 AssistantPage 时,对话与「正在流式的回答」都不丢——
// 流式回调写的是这个单例(经 setMessagesOf),回到页面 useSyncExternalStore 重新订阅即看到(并续流)。

interface StoreState {
  conversations: Conversation[]
  activeId: string
}

let state: StoreState = { conversations: loadList(), activeId: makeSessionId() }
const listeners = new Set<() => void>()
const EMPTY: ChatMessage[] = []

function emit(): void {
  for (const l of listeners) l()
}

let saveTimer: ReturnType<typeof setTimeout> | undefined
function scheduleSave(): void {
  clearTimeout(saveTimer)
  // 防抖:流式逐字会高频更新,400ms 合并写;只存有消息的会话,丢弃空草稿。
  saveTimer = setTimeout(() => {
    const keep = state.conversations.filter((c) => c.messages.length > 0)
    try {
      localStorage.setItem(LS_KEY, JSON.stringify({ conversations: keep }))
    } catch {
      /* 配额/隐私模式,忽略 */
    }
  }, 400)
}

function setState(next: StoreState): void {
  state = next
  emit()
  scheduleSave()
}

/** 更新某会话的消息(不存在则建)。模块级稳定函数:流式回调按捕获的 id 定向写,跨卸载/切换都不丢。 */
export function setMessagesOf(id: string, updater: (prev: ChatMessage[]) => ChatMessage[]): void {
  const cs = state.conversations
  const idx = cs.findIndex((c) => c.id === id)
  const prev = idx >= 0 ? cs[idx].messages : EMPTY
  const messages = updater(prev)
  const patch = { id, title: deriveTitle(messages), messages, updatedAt: Date.now() }
  const conversations =
    idx >= 0 ? cs.map((c, i) => (i === idx ? { ...c, ...patch } : c)) : [...cs, patch]
  setState({ ...state, conversations })
}

/** 新建会话:开一条新草稿(空态)。旧会话记忆原样保留,切回去还在。返回新 id。 */
export function newConversation(): string {
  const id = makeSessionId()
  setState({ ...state, activeId: id })
  return id
}

export function selectConversation(id: string): void {
  setState({ ...state, activeId: id })
}

/** 删除某会话:移出列表;删的是当前会话则回到一条新草稿。 */
export function removeConversation(id: string): void {
  const conversations = state.conversations.filter((c) => c.id !== id)
  const activeId = state.activeId === id ? makeSessionId() : state.activeId
  setState({ conversations, activeId })
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  return () => listeners.delete(cb)
}
function getSnapshot(): StoreState {
  return state
}

/**
 * 助手多会话状态(模块级单例 + useSyncExternalStore)。每条会话独立 session_id(切换即切上下文);
 * 状态在组件外,故流式回答中途切页/切会话都不丢,回来还能继续看它流完。
 */
export function useConversations() {
  const s = useSyncExternalStore(subscribe, getSnapshot)
  const active = s.conversations.find((c) => c.id === s.activeId)
  const messages = active?.messages ?? EMPTY
  // 侧栏只列有消息的会话,最近在前。
  const history = s.conversations
    .filter((c) => c.messages.length > 0)
    .sort((a, b) => b.updatedAt - a.updatedAt)

  return {
    activeId: s.activeId,
    messages,
    history,
    setMessagesOf,
    newConversation,
    selectConversation,
    removeConversation,
  }
}
