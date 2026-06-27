import { Package } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { lazy } from 'react'
import { scanResourceSpec } from './backup'

export const supplyModule = defineFeature({
  id: 'supply',
  label: '供应链',
  labelKey: 'app.nav.supply',
  icon: Package,
  group: '管控',
  order: 50,
  requires: 'supply.view',
  component: lazy(() => import('./supply-page').then((m) => ({ default: m.SupplyPage }))),
  resources: [scanResourceSpec],
  actions: [
    {
      id: 'nav.supply',
      label: '打开供应链',
      description: '导航到供应链组件扫描页',
      risk: 'read_only',
      requires: ['supply.view'],
      navTo: 'supply',
    },
  ],
})
