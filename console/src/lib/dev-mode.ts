import { useSyncExternalStore } from 'react'

/**
 * 开发者模式开关(localStorage 持久化,跨组件同步)。
 *
 * 控制台里一部分页面只有**我们开发者/答辩**用得上(评测验证、网关实测),真·政企管理员
 * 日常用不到。默认关闭 → 这些页从导航/路由隐藏,管理员看到的是干净的运营视图;
 * 在「系统设置 · 开发者」里打开后才显示(模块以 `FeatureModule.dev` 标记,见 `lib/module`)。
 */
const KEY = 'fulcrum.dev_mode'

function read(): boolean {
  try {
    return localStorage.getItem(KEY) === '1'
  } catch {
    return false
  }
}

let enabled = read()
const listeners = new Set<() => void>()

export function getDevMode(): boolean {
  return enabled
}

export function setDevMode(value: boolean): void {
  enabled = value
  try {
    localStorage.setItem(KEY, value ? '1' : '0')
  } catch {
    /* 隐私模式/禁用存储时仅内存生效,不报错 */
  }
  listeners.forEach((l) => l())
}

/** 订阅开发者模式;返回 [是否开启, 设置函数]。任意组件读到的值始终同步。 */
export function useDevMode(): [boolean, (value: boolean) => void] {
  const value = useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    getDevMode,
    getDevMode,
  )
  return [value, setDevMode]
}
