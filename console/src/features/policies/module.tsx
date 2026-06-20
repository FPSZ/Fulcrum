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
  actions: [
    {
      id: 'nav.policies',
      label: '打开策略中心',
      description: '导航到策略中心页(当前装配的策略规则)',
      risk: 'read_only',
      requires: ['policies.view'],
      navTo: 'policies',
    },
    {
      id: 'policy.disable',
      label: '停用策略',
      description: '临时停用一条安全策略规则(高危:会削弱防护,必须二次确认)',
      risk: 'high',
      requires: ['policies.manage'],
      argsHint: '形如 {"policy_id":"POL-014"}',
    },
  ],
})
