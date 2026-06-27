import { useSyncExternalStore } from 'react'
import { zh } from './locales/zh'
import { en } from './locales/en'

/**
 * 轻量自研 i18n —— 无第三方依赖、key 类型安全、私有化可控(plan:政企可控诉求)。
 *
 * 设计对齐 `lib/dev-mode`:模块级 store + `useSyncExternalStore` 跨组件同步 + localStorage
 * 持久化。`zh` 是**词典真源**(永远完整),`MessageKey` 由它派生 → 写错 key 即编译失败;
 * `en` 是 `Partial`(可逐步补,缺项自动回退中文)。组件用 `useTranslation()`(订阅语言变化、
 * 切换即重渲染),非组件场景(纯函数里)用裸 `t()`(读当前语言,不参与重渲染)。
 *
 * 占位插值:文案里写 `{name}`,调用 `t('k', { name })` 即替换;缺参保留 `{name}` 不抛错。
 */
export type Locale = 'zh' | 'en'
export type MessageKey = keyof typeof zh

const DICTS: Record<Locale, Partial<Record<MessageKey, string>>> = { zh, en }
const KEY = 'fulcrum.locale'
const SUPPORTED: readonly Locale[] = ['zh', 'en']

function read(): Locale {
  try {
    const v = localStorage.getItem(KEY)
    return v === 'en' || v === 'zh' ? v : 'zh'
  } catch {
    return 'zh'
  }
}

let locale: Locale = read()
const listeners = new Set<() => void>()

export function getLocale(): Locale {
  return locale
}

export function setLocale(value: Locale): void {
  if (!SUPPORTED.includes(value) || value === locale) return
  locale = value
  try {
    localStorage.setItem(KEY, value)
  } catch {
    /* 隐私模式/禁用存储时仅内存生效,不报错 */
  }
  listeners.forEach((l) => l())
}

function interpolate(text: string, vars?: Record<string, string | number>): string {
  if (!vars) return text
  return text.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m))
}

/**
 * 取某 key 的当前语言文案;缺项回退中文真源,再缺(理论上不会)回退 key 本身。
 * 可选 `vars` 做 `{name}` 占位替换。**纯函数**:读模块级 `locale`,组件外亦可用。
 */
export function t(key: MessageKey, vars?: Record<string, string | number>): string {
  const text = DICTS[locale][key] ?? zh[key] ?? (key as string)
  return interpolate(text, vars)
}

/** 组件内用:订阅语言变化(切换即重渲染),返回 { t, locale, setLocale }。 */
export function useTranslation(): {
  t: typeof t
  locale: Locale
  setLocale: typeof setLocale
} {
  const current = useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    getLocale,
    getLocale,
  )
  return { t, locale: current, setLocale }
}
