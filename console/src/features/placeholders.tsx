import { FileSearch, FlaskConical, Package, Plug, Scale } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { Placeholder } from '@/components/app/placeholder'

/** 尚未实现的页面:占位模块。建设到对应页面时,把 component 换成真实页面即可。 */
const ph = (title: string) => () => <Placeholder title={title} />

export const policiesModule = defineFeature({
  id: 'policies', label: '策略中心', icon: Scale, group: '管控', order: 30, component: ph('策略中心'),
})
export const toolsModule = defineFeature({
  id: 'tools', label: '工具网关', icon: Plug, group: '管控', order: 40, badge: 5, danger: true, component: ph('工具网关'),
})
export const supplyModule = defineFeature({
  id: 'supply', label: '供应链', icon: Package, group: '管控', order: 50, badge: 2, component: ph('供应链'),
})
export const auditModule = defineFeature({
  id: 'audit', label: '审计溯源', icon: FileSearch, group: '取证', order: 60, component: ph('审计溯源'),
})
export const evalModule = defineFeature({
  id: 'eval', label: '评测验证', icon: FlaskConical, group: '取证', order: 70, component: ph('评测验证'),
})
