import { FileSearch } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { lazy } from 'react'
import { auditResourceSpec } from './backup'

export const auditModule = defineFeature({
  id: 'audit',
  label: '审计溯源',
  icon: FileSearch,
  group: '取证',
  order: 60,
  requires: 'audit.view',
  component: lazy(() => import('./audit-page').then((m) => ({ default: m.AuditPage }))),
  resources: [auditResourceSpec],
  actions: [
    {
      id: 'nav.audit',
      label: '打开审计溯源',
      description: '导航到审计溯源页(会话 hash-chain)',
      risk: 'read_only',
      requires: ['audit.view'],
      navTo: 'audit',
    },
  ],
})
