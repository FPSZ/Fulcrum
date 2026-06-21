import { ShieldCheck } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { GatewayPage } from './gateway-page'

export const gatewayModule = defineFeature({
  id: 'gateway',
  label: '网关实测',
  icon: ShieldCheck,
  group: '监测',
  order: 15, // 紧随安全总览,作为「看网关如何防护」的入口
  requires: 'events.view',
  component: GatewayPage,
  actions: [
    {
      id: 'nav.gateway',
      label: '打开网关实测',
      description: '导航到网关实测页(把请求送进透明安全网关,看分级处置与端到端链路)',
      risk: 'read_only',
      requires: ['events.view'],
      navTo: 'gateway',
    },
  ],
})
