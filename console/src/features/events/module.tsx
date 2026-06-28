import { Activity } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { lazy } from 'react'
import { eventResourceSpec } from './backup'

export const eventsModule = defineFeature({
  id: 'events',
  label: '实时事件',
  labelKey: 'app.nav.events',
  icon: Activity,
  group: '监测',
  order: 20,
  requires: 'events.view',
  component: lazy(() => import('./events-page').then((m) => ({ default: m.EventsPage }))),
  resources: [eventResourceSpec],
  actions: [
    {
      id: 'nav.events',
      label: '打开实时事件',
      description: '导航到实时事件页(逐条安全事件与证据链)',
      risk: 'read_only',
      requires: ['events.view'],
      navTo: 'events',
    },
    {
      id: 'filter.events',
      label: '筛选实时事件',
      description: '在实时事件页按处置或严重度筛选',
      risk: 'read_only',
      requires: ['events.view'],
      argsHint: '可选 {"disposition":"block|approve|allow","level":"low|medium|high|critical"}',
      navTo: 'events',
    },
  ],
})
