import { Users } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { UsersPage } from './users-page'

/** 组织与成员(成员 / 团队 / 角色 / 账号审批)。需 users.view;团队负责人亦可见(只管本团队)。 */
export const usersModule = defineFeature({
  id: 'admin-users',
  label: '组织与成员',
  icon: Users,
  group: '系统',
  order: 80,
  requires: 'users.view',
  leadVisible: true,
  component: UsersPage,
})
