import { useCallback, useEffect, useMemo, useState } from 'react'
import { Segmented, toast, type SegmentedItem } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import {
  listDepartments,
  listPermissions,
  listRoles,
  memberStats,
  type Department,
  type PermissionDef,
  type Role,
} from '@/lib/admin'
import { MembersTab } from './members-tab'
import { DepartmentsTab } from './departments-tab'
import { RolesTab } from './roles-tab'
import { ApprovalsTab } from './approvals-tab'

type Tab = 'members' | 'departments' | 'roles' | 'approvals'

export function UsersPage() {
  const { has } = useAuth()
  const [tab, setTab] = useState<Tab>('members')
  const [departments, setDepartments] = useState<Department[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [permissions, setPermissions] = useState<PermissionDef[]>([])
  const [stats, setStats] = useState<Record<string, number>>({})

  const reloadMeta = useCallback(async () => {
    try {
      const [d, r, p, s] = await Promise.all([
        listDepartments(),
        listRoles(),
        listPermissions(),
        memberStats(),
      ])
      setDepartments(d)
      setRoles(r)
      setPermissions(p)
      setStats(s)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '加载失败')
    }
  }, [])

  useEffect(() => {
    void reloadMeta()
  }, [reloadMeta])

  const canManageUsers = has('users.manage')
  const canManageDept = has('dept.manage')
  const canManageRoles = has('roles.manage')
  const canApprove = has('account.approve')

  const total = (stats.active ?? 0) + (stats.disabled ?? 0) + (stats.left ?? 0)
  const statItems = useMemo(
    () => [
      { label: '成员总数', value: total },
      { label: '在职', value: stats.active ?? 0 },
      { label: '停用', value: stats.disabled ?? 0 },
      { label: '部门', value: departments.length },
      { label: '角色', value: roles.length },
      { label: '待审批', value: stats.pending ?? 0, highlight: (stats.pending ?? 0) > 0 },
    ],
    [stats, departments.length, roles.length, total],
  )

  const tabs = useMemo<SegmentedItem[]>(() => {
    const base: SegmentedItem[] = [
      { value: 'members', label: '成员' },
      { value: 'departments', label: '组织架构' },
      { value: 'roles', label: '角色权限' },
    ]
    if (canApprove)
      base.push({ value: 'approvals', label: '待审批', count: stats.pending || undefined })
    return base
  }, [canApprove, stats.pending])

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-hidden p-5">
      {/* 概览统计 */}
      <div className="grid shrink-0 grid-cols-3 gap-2.5 sm:grid-cols-6">
        {statItems.map((s) => (
          <div key={s.label} className="rounded-[12px] border border-line bg-surface px-3.5 py-2.5 shadow-card">
            <div className="text-[12.5px] text-ink-3">{s.label}</div>
            <div
              className={`mt-0.5 font-data text-[22px] font-semibold tabular-nums ${
                s.highlight ? 'text-accent' : 'text-ink'
              }`}
            >
              {s.value}
            </div>
          </div>
        ))}
      </div>

      <Segmented
        className="shrink-0 self-start"
        value={tab}
        onValueChange={(v) => setTab(v as Tab)}
        items={tabs}
      />

      {tab === 'members' && (
        <MembersTab
          departments={departments}
          roles={roles}
          canManage={canManageUsers}
          onChanged={reloadMeta}
        />
      )}
      {tab === 'departments' && (
        <DepartmentsTab departments={departments} canManage={canManageDept} onChanged={reloadMeta} />
      )}
      {tab === 'roles' && (
        <RolesTab
          roles={roles}
          permissions={permissions}
          canManage={canManageRoles}
          onChanged={reloadMeta}
        />
      )}
      {tab === 'approvals' && canApprove && (
        <ApprovalsTab departments={departments} roles={roles} onChanged={reloadMeta} />
      )}
    </div>
  )
}
