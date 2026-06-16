import { Package, Plug } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { Placeholder } from '@/components/app/placeholder'

/** 尚未实现的页面:占位模块。建设到对应页面时,把 component 换成真实页面即可。 */
const ph = (title: string) => () => <Placeholder title={title} />

export const toolsModule = defineFeature({
  id: 'tools', label: '工具网关', icon: Plug, group: '管控', order: 40, badge: 5, danger: true, requires: 'tools.view', component: ph('工具网关'),
})
export const supplyModule = defineFeature({
  id: 'supply', label: '供应链', icon: Package, group: '管控', order: 50, badge: 2, requires: 'supply.view', component: ph('供应链'),
})
