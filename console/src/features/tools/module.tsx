import { Plug } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { lazy } from 'react'
import { toolCallResourceSpec } from './backup'

export const toolsModule = defineFeature({
  id: 'tools',
  label: '工具网关',
  icon: Plug,
  group: '管控',
  order: 40,
  danger: true,
  requires: 'tools.view',
  component: lazy(() => import('./tools-page').then((m) => ({ default: m.ToolsPage }))),
  resources: [toolCallResourceSpec],
  actions: [
    {
      id: 'nav.tools',
      label: '打开工具网关',
      description: '导航到工具调用治理页',
      risk: 'read_only',
      requires: ['tools.view'],
      navTo: 'tools',
    },
  ],
})
