import { Scale } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { PoliciesPage } from './policies-page'

export const policiesModule = defineFeature({
  id: 'policies',
  label: '策略中心',
  icon: Scale,
  group: '管控',
  order: 30,
  requires: 'policies.view',
  component: PoliciesPage,
})
