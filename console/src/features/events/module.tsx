import { Activity } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { EventsPage } from './events-page'
import { eventResourceSpec } from './backup'

export const eventsModule = defineFeature({
  id: 'events',
  label: '实时事件',
  icon: Activity,
  group: '监测',
  order: 20,
  badge: 38,
  component: EventsPage,
  resources: [eventResourceSpec],
})
