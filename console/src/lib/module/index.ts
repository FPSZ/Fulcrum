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

/** AI 操作助手可调动作的风险分级:只读可直接执行;一般需留意;高危必须二次确认。 */
export type ModuleActionRisk = 'read_only' | 'normal' | 'high'

/**
 * 一个功能模块贡献给「AI 操作助手」的可调动作。
 * 注册即进助手动作目录 —— 与后端 @capability 注册动作对称:模块自带动作,装配清单一接就到。
 * (前端目录仅作 seed/回退展示;运行时真目录仍由后端 GET /assistant/actions 按权限点过滤。)
 */
export interface ModuleAction {
  /** 动作 id(与后端 catalog 同名,如 nav.events / policy.disable) */
  id: string
  /** 动作显示名 */
  label: string
  /** 动作说明 */
  description: string
  /** 风险分级 */
  risk: ModuleActionRisk
  /** 调用所需权限点(RBAC);助手能调的动作 = 角色能点的按钮 */
  requires: string[]
  /** 参数提示(JSON 形态);只读导航类可省 */
  argsHint?: string
  /** 只读动作可由助手面板直接执行时跳转的目标模块 id;缺省=面板不直接执行(仍走各自守卫端点) */
  navTo?: string
}

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
  /** 团队负责人也可见:即便其角色不含 requires 权限,只要是某团队负责人即可进(plan/13 §6)。
   *  用于成员/团队管理这类"组长须管本团队"的页面;进去后数据仍按可管团队范围过滤。 */
  leadVisible?: boolean
  /** 开发者专属页:仅开发/答辩用(评测验证、网关实测),默认隐藏,开「开发者模式」才显示 */
  dev?: boolean
  /** 该模块贡献给 AI 操作助手的可调动作(注册即进助手动作目录,与后端 catalog 对称) */
  actions?: ModuleAction[]
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

/** 汇总所有已注册模块贡献的助手可调动作(按模块 order 顺序展开)。 */
export function getModuleActions(): ModuleAction[] {
  return getFeatures().flatMap((f) => f.actions ?? [])
}

/** 按权限 + 开发者模式过滤后的可见模块(无 requires 的恒可见;dev 页仅 devMode 开启时显;
 *  leadVisible 模块对团队负责人放行,即便其角色不含 requires 权限) */
export function getFeaturesFor(
  can: (perm: string) => boolean,
  devMode = false,
  isLead = false,
): FeatureModule[] {
  return getFeatures().filter(
    (f) =>
      (!f.requires || can(f.requires) || (isLead && f.leadVisible)) && (!f.dev || devMode),
  )
}

export function getFeature(id: string): FeatureModule | undefined {
  return registry.get(id)
}

/** 默认进入的模块 id(order 最小者) */
export function getDefaultFeatureId(): string {
  return getFeatures()[0]?.id ?? ''
}

/** 当前权限下的默认模块 id(可见集合里 order 最小者) */
export function getDefaultFeatureIdFor(
  can: (perm: string) => boolean,
  devMode = false,
  isLead = false,
): string {
  return getFeaturesFor(can, devMode, isLead)[0]?.id ?? ''
}
