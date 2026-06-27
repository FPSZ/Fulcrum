import { Bot } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { lazy } from 'react'

export const assistantModule = defineFeature({
  id: 'assistant',
  label: '操作助手',
  labelKey: 'app.nav.assistant',
  icon: Bot,
  group: '管控',
  order: 60,
  requires: 'ai.operate',
  component: lazy(() => import('./assistant-page').then((m) => ({ default: m.AssistantPage }))),
})
