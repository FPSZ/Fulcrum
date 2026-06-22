import { useSyncExternalStore } from 'react'

/**
 * 布尔偏好工厂 —— localStorage 持久化 + 跨组件同步(useSyncExternalStore)。
 * 给"开发者模式""对话展示"等开关共用一套实现,避免各写一份。
 */
export function createBoolPref(key: string, fallback: boolean) {
  const read = (): boolean => {
    try {
      const v = localStorage.getItem(key)
      return v === null ? fallback : v === '1'
    } catch {
      return fallback
    }
  }
  let value = read()
  const listeners = new Set<() => void>()

  const get = (): boolean => value
  const set = (v: boolean): void => {
    value = v
    try {
      localStorage.setItem(key, v ? '1' : '0')
    } catch {
      /* 隐私模式/禁用存储时仅内存生效 */
    }
    listeners.forEach((l) => l())
  }
  const use = (): [boolean, (v: boolean) => void] => {
    const val = useSyncExternalStore(
      (cb) => {
        listeners.add(cb)
        return () => listeners.delete(cb)
      },
      get,
      get,
    )
    return [val, set]
  }
  return { get, set, use }
}
