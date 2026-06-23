import { useCallback, useEffect, useState } from 'react'
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

function deriveTitle(messages: ChatMessage[]): string {
  const firstUser = messages.find((m) => m.role === 'user')
  const t = (firstUser?.text ?? '').trim().replace(/\s+/g, ' ')
  return t ? (t.length > 22 ? `${t.slice(0, 22)}…` : t) : '新对话'
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

/**
 * 助手多会话状态(前端 localStorage)。每条会话独立 session_id —— 切换会话即切换后端记忆,
 * 上下文各自延续。空草稿(未发消息)不入历史、不落盘,与 Kimi「新建会话直到首条消息才进历史」一致。
 */
export function useConversations() {
  const [conversations, setConversations] = useState<Conversation[]>(() => loadList())
  // 打开页面默认是一条「新对话」草稿(空态),历史在侧栏列出。
  const [activeId, setActiveId] = useState<string>(() => makeSessionId())

  // 落盘(防抖):流式逐字会高频更新,400ms 合并写;只存有消息的会话,丢弃空草稿。
  useEffect(() => {
    const t = setTimeout(() => {
      const keep = conversations.filter((c) => c.messages.length > 0)
      try {
        localStorage.setItem(LS_KEY, JSON.stringify({ conversations: keep }))
      } catch {
        /* 配额/隐私模式,忽略 */
      }
    }, 400)
    return () => clearTimeout(t)
  }, [conversations])

  /** 更新某会话的消息(不存在则建)。供发送/流式回调按捕获到的会话 id 定向写,不受切换影响。 */
  const setMessagesOf = useCallback(
    (id: string, updater: (prev: ChatMessage[]) => ChatMessage[]) => {
      setConversations((cs) => {
        const idx = cs.findIndex((c) => c.id === id)
        const prev = idx >= 0 ? cs[idx].messages : []
        const messages = updater(prev)
        const patch = { id, title: deriveTitle(messages), messages, updatedAt: Date.now() }
        if (idx >= 0) {
          const next = [...cs]
          next[idx] = { ...cs[idx], ...patch }
          return next
        }
        return [...cs, patch]
      })
    },
    [],
  )

  /** 新建会话:开一条新草稿(空态)。旧会话记忆原样保留,切回去还在。 */
  const newConversation = useCallback(() => {
    const id = makeSessionId()
    setActiveId(id)
    return id
  }, [])

  const selectConversation = useCallback((id: string) => setActiveId(id), [])

  /** 删除某会话:移出列表;删的是当前会话则回到一条新草稿。返回被删 id(供清后端记忆)。 */
  const removeConversation = useCallback(
    (id: string) => {
      setConversations((cs) => cs.filter((c) => c.id !== id))
      setActiveId((cur) => (cur === id ? makeSessionId() : cur))
    },
    [],
  )

  const active = conversations.find((c) => c.id === activeId)
  const messages = active?.messages ?? []
  // 侧栏只列有消息的会话,最近在前。
  const history = conversations
    .filter((c) => c.messages.length > 0)
    .sort((a, b) => b.updatedAt - a.updatedAt)

  return {
    activeId,
    messages,
    history,
    setMessagesOf,
    newConversation,
    selectConversation,
    removeConversation,
  }
}
