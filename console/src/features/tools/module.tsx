import { Plug } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { ToolsPage } from './tools-page'

export const toolsModule = defineFeature({
  id: 'tools',
  label: '工具网关',
  icon: Plug,
  group: '管控',
  order: 40,
  badge: 5,
  danger: true,
  requires: 'tools.view',
  component: ToolsPage,
})
