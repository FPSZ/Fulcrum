import { Users } from 'lucide-react'
import { defineFeature } from '@/lib/module'
import { lazy } from 'react'

/** 用户管理(组织架构 + 成员 + 角色权限 + 账号审批)。需 users.view 权限可见。 */
export const usersModule = defineFeature({
  id: 'admin-users',
  label: '用户管理',
  icon: Users,
  group: '系统',
  order: 80,
  requires: 'users.view',
  component: lazy(() => import('./users-page').then((m) => ({ default: m.UsersPage }))),
})
