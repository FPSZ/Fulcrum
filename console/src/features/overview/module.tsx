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
})
