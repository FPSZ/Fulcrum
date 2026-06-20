import { Gauge } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { OverviewPage } from './overview-page'
import { overviewResourceSpec } from './backup'

export const overviewModule = defineFeature({
  id: 'overview',
  label: '安全总览',
  icon: Gauge,
  group: '监测',
  order: 10,
  requires: 'overview.view',
  component: OverviewPage,
  resources: [overviewResourceSpec],
  actions: [
    {
      id: 'nav.overview',
      label: '打开安全总览',
      description: '导航到安全总览页(KPI + 实时事件概览)',
      risk: 'read_only',
      requires: ['overview.view'],
      navTo: 'overview',
    },
  ],
})
