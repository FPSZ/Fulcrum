import type { z } from 'zod'

/**
 * 资源导入规格。每种可备份/导入的资源注册一条:
 * - kind:   备份文件 resources 下的键(如 'events')
 * - label:  中文显示名
 * - schema: 校验该资源数组的 zod schema(zod 解析失败则跳过该资源,不污染数据)
 *
 * 扩展方式:新增资源 = 新写一个 ResourceSpec 并 registerResource(),导入器/导出器零改。
 */
export interface ResourceSpec {
  kind: string
  label: string
  schema: z.ZodTypeAny
}

const specs = new Map<string, ResourceSpec>()

export function registerResource(spec: ResourceSpec): void {
  // 与 registerFeature 一致:重复 kind 抛错,避免静默覆盖丢资源(潜在数据 bug)。
  if (specs.has(spec.kind)) throw new Error(`重复注册备份资源: ${spec.kind}`)
  specs.set(spec.kind, spec)
}

export function getResourceSpec(kind: string): ResourceSpec | undefined {
  return specs.get(kind)
}

export function getResourceSpecs(): ResourceSpec[] {
  return [...specs.values()]
}
