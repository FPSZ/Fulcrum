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
  specs.set(spec.kind, spec)
}

export function getResourceSpec(kind: string): ResourceSpec | undefined {
  return specs.get(kind)
}

export function getResourceSpecs(): ResourceSpec[] {
  return [...specs.values()]
}
