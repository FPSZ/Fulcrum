import { useEffect, useRef, useState } from 'react'
import type { SecurityEvent } from '../events/types'

/**
 * 实时监测数据流。
 *
 * 真实部署时这里换成 SSE / WebSocket 订阅安全网关的事件总线;
 * 当前无后端,以载入备份里的事件为「样本池」,按秒推进合成实时流,
 * 让总览成为每秒刷新的实时面板(及时发现新出现的高危事件)。
 */

const WINDOW = 60 // 秒级滚动曲线窗口(近 60 秒)
const FEED_CAP = 40 // 实时事件流最多保留条数

export interface LiveState {
  now: Date
  /** 实时事件流(最新在前) */
  feed: SecurityEvent[]
  /** 本 tick 新到事件的 id(用于入场高亮) */
  freshIds: Set<string>
  /** 近 60 秒每秒攻击尝试数(末位=当前秒) */
  perSecond: number[]
  /** 自进入面板起新增的处置计数(用于 KPI 实时跳动) */
  added: { controlled: number; blocked: number; sanitized: number }
  /** 当前事件流中待审批(approve)条数 */
  pending: number
}

function pad(n: number): string {
  return String(n).padStart(2, '0')
}
function clockTime(d: Date): string {
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
function rid(): string {
  return Math.random().toString(16).slice(2, 8)
}
/** 这一秒到几条事件:多数 0,偶发 1,极少 2(突发) */
function arrivalsThisTick(): number {
  const r = Math.random()
  if (r > 0.965) return 2
  if (r > 0.78) return 1
  return 0
}

export function useLive(seed: SecurityEvent[], enabled: boolean): LiveState {
  const [now, setNow] = useState(() => new Date())
  const [feed, setFeed] = useState<SecurityEvent[]>(() => seed.slice(0, 12))
  const [freshIds, setFreshIds] = useState<Set<string>>(() => new Set())
  const [perSecond, setPerSecond] = useState<number[]>(() =>
    Array.from({ length: WINDOW }, () => {
      const r = Math.random()
      return r > 0.96 ? 2 : r > 0.78 ? 1 : 0
    }),
  )
  const added = useRef({ controlled: 0, blocked: 0, sanitized: 0 })
  const seedRef = useRef(seed)
  seedRef.current = seed

  useEffect(() => {
    if (!enabled || seed.length === 0) return
    const timer = setInterval(() => {
      const d = new Date()
      const pool = seedRef.current
      const n = pool.length ? arrivalsThisTick() : 0
      const fresh: SecurityEvent[] = []
      for (let i = 0; i < n; i++) {
        const t = pool[Math.floor(Math.random() * pool.length)]
        fresh.push({ ...t, id: rid(), sess: rid(), time: clockTime(d) })
      }
      setNow(d)
      setPerSecond((prev) => [...prev.slice(1), n])
      setFreshIds(new Set(fresh.map((e) => e.id)))
      if (fresh.length) {
        for (const e of fresh) {
          added.current.controlled += 1
          if (e.disp === 'block') added.current.blocked += 1
          if (e.disp === 'sanitize') added.current.sanitized += 1
        }
        setFeed((prev) => [...fresh, ...prev].slice(0, FEED_CAP))
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [enabled, seed])

  const pending = feed.filter((e) => e.disp === 'approve').length
  return { now, feed, freshIds, perSecond, added: added.current, pending }
}
