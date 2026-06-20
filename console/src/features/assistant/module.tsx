import { Bot } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { AssistantPage } from './assistant-page'

export const assistantModule = defineFeature({
  id: 'assistant',
  label: '操作助手',
  icon: Bot,
  group: '管控',
  order: 60,
  requires: 'ai.operate',
  component: AssistantPage,
})
