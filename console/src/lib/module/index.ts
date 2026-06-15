import type { ComponentType } from 'react'
import type { LucideIcon } from 'lucide-react'
import type { ResourceSpec } from '@/lib/backup'

/**
 * 前端功能模块插件系统
 * ─────────────────────────────────────────────────────────────
 * 一个"功能" = 一个自包含模块:导航项 + 页面 + 它贡献的可备份资源。
 * 注册一次,侧栏导航、路由、备份资源全部自动接上 —— 与后端 @capability + 注册表对称。
 *
 * 加一个页面只需:
 *   1. 写页面组件
 *   2. defineFeature({...}) 导出一个模块
 *   3. 在 features/register.ts 的清单里加一行
 * 不改 App.tsx、不改 Sidebar、不改别的模块。
 */

/** 导航分组及其展示顺序(唯一真源) */
export const FEATURE_GROUPS = ['监测', '管控', '取证', '系统'] as const
export type FeatureGroup = (typeof FEATURE_GROUPS)[number]

export interface FeatureModule {
  /** 唯一 id,也是路由 key */
  id: string
  /** 导航与页头显示名 */
  label: string
  /** 导航图标(lucide) */
  icon: LucideIcon
  /** 所属导航分组 */
  group: FeatureGroup
  /** 组内排序(小在前),默认 100 */
  order?: number
  /** 导航右侧计数徽标 */
  badge?: number
  /** 计数是否以告警色强调 */
  danger?: boolean
  /** 页面组件 */
  component: ComponentType
  /** 该模块贡献的可备份/可导入资源(自动注册进备份系统) */
  resources?: ResourceSpec[]
  /** 可见所需权限点(RBAC):缺省=人人可见;设置后无此权限者导航/路由都看不到 */
  requires?: string
}

/** 身份函数:仅为获得类型检查与补全 */
export function defineFeature(m: FeatureModule): FeatureModule {
  return m
}

const registry = new Map<string, FeatureModule>()

export function registerFeature(m: FeatureModule): void {
  if (registry.has(m.id)) throw new Error(`重复注册功能模块: ${m.id}`)
  registry.set(m.id, m)
}

/** 按 order 升序返回所有模块 */
export function getFeatures(): FeatureModule[] {
  return [...registry.values()].sort((a, b) => (a.order ?? 100) - (b.order ?? 100))
}

/** 按权限过滤后的可见模块(无 requires 的恒可见) */
export function getFeaturesFor(can: (perm: string) => boolean): FeatureModule[] {
  return getFeatures().filter((f) => !f.requires || can(f.requires))
}

export function getFeature(id: string): FeatureModule | undefined {
  return registry.get(id)
}

/** 默认进入的模块 id(order 最小者) */
export function getDefaultFeatureId(): string {
  return getFeatures()[0]?.id ?? ''
}

/** 当前权限下的默认模块 id(可见集合里 order 最小者) */
export function getDefaultFeatureIdFor(can: (perm: string) => boolean): string {
  return getFeaturesFor(can)[0]?.id ?? ''
}
