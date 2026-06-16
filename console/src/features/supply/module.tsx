import { Package } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { SupplyPage } from './supply-page'

export const supplyModule = defineFeature({
  id: 'supply',
  label: '供应链',
  icon: Package,
  group: '管控',
  order: 50,
  badge: 2,
  requires: 'supply.view',
  component: SupplyPage,
})
