import { useCallback, useEffect, useMemo, useState } from 'react'
import { Building2, Inbox, Shield, Users } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Badge, toast } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/lib/i18n'
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

/**
 * 组织与成员后台(plan/13 §10)—— 学 GitHub 组织设置 / 飞书管理后台的信息架构:
 * **左侧分区导航 + 每区一张实体页**,组织级 / 团队级范围在 IA 上一眼可辨,不再三栏挤一页。
 * 范围化:团队负责人进来只见「本团队」视图(成员行级过滤、团队只管自己的),组织管理员见全局。
 */
type SectionId = 'members' | 'teams' | 'roles' | 'approvals'

interface SectionDef {
  id: SectionId
  label: string
  icon: LucideIcon
  desc: string
  badge?: number
}

export function UsersPage() {
  const { t } = useTranslation()
  const { has, isLead } = useAuth()
  const [section, setSection] = useState<SectionId>('members')
  const [departments, setDepartments] = useState<Department[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [permissions, setPermissions] = useState<PermissionDef[]>([])
  const [stats, setStats] = useState<Record<string, number>>({})

  const canViewOrg = has('users.view') // 组织级读权(看全局统计 / 角色管理)
  const canManageUsers = has('users.manage')
  const canManageDept = has('dept.manage')
  const canManageRoles = has('roles.manage')
  const canApprove = has('account.approve') || isLead
  const scopedView = isLead && !canManageUsers // 纯团队负责人:仅本团队视图

  const reloadMeta = useCallback(async () => {
    try {
      const [d, r, p] = await Promise.all([listDepartments(), listRoles(), listPermissions()])
      setDepartments(d)
      setRoles(r)
      setPermissions(p)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.members.load_failed'))
    }
    // 全局统计仅组织级读权可取;团队负责人无权,静默跳过(其视图不展示全局数)。
    if (canViewOrg) {
      try {
        setStats(await memberStats())
      } catch {
        /* 忽略 */
      }
    }
  }, [canViewOrg])

  useEffect(() => {
    void reloadMeta()
  }, [reloadMeta])

  const sections = useMemo<SectionDef[]>(() => {
    const list: SectionDef[] = [
      {
        id: 'members',
        label: t('admin.section.members'),
        icon: Users,
        desc: scopedView ? t('admin.section.members.desc_scoped') : t('admin.section.members.desc'),
      },
      {
        id: 'teams',
        label: t('admin.section.teams'),
        icon: Building2,
        desc: t('admin.section.teams.desc'),
      },
    ]
    if (canViewOrg)
      list.push({
        id: 'roles',
        label: t('admin.section.roles'),
        icon: Shield,
        desc: t('admin.section.roles.desc'),
      })
    if (canApprove)
      list.push({
        id: 'approvals',
        label: t('admin.section.approvals'),
        icon: Inbox,
        desc: t('admin.section.approvals.desc'),
        badge: stats.pending || undefined,
      })
    return list
  }, [t, canViewOrg, canApprove, scopedView, stats.pending])

  // 若当前分区因权限不可见(如负责人切到隐藏的角色页),回退到成员页。
  useEffect(() => {
    if (!sections.some((s) => s.id === section)) setSection('members')
  }, [sections, section])

  const current = sections.find((s) => s.id === section) ?? sections[0]

  return (
    <div className="flex h-full min-h-0 gap-4 overflow-hidden p-4 md:p-5" data-no-reveal>
      {/* 左:分区导航(桌面竖排;移动端横向可滑) */}
      <nav className="flex shrink-0 gap-1 overflow-x-auto rounded-[12px] border border-line bg-surface/60 p-2 max-md:order-first md:w-52 md:flex-col md:overflow-visible">
        {canViewOrg && (
          <div className="hidden px-2 pb-1 pt-1 text-[12px] font-semibold uppercase tracking-wide text-ink-mute md:block">
            {t('admin.nav.group')}
          </div>
        )}
        {sections.map((s) => {
          const active = s.id === section
          const Icon = s.icon
          return (
            <button
              key={s.id}
              type="button"
              onClick={() => setSection(s.id)}
              className={cn(
                'focus-ring flex shrink-0 items-center gap-2.5 rounded-[10px] px-2.5 py-2 text-left text-[14.5px] transition-colors md:w-full',
                active
                  ? 'bg-accent/10 font-semibold text-accent-ink'
                  : 'text-ink-2 hover:bg-surface-2',
              )}
            >
              <Icon
                className={cn('h-[17px] w-[17px] shrink-0', active ? 'text-accent' : 'text-ink-3')}
                strokeWidth={1.9}
              />
              <span className="min-w-0 flex-1 truncate">{s.label}</span>
              {typeof s.badge === 'number' && (
                <span className="tabnum grid h-[18px] min-w-[18px] place-items-center rounded-full bg-accent px-1.5 text-[12px] font-bold text-white">
                  {s.badge}
                </span>
              )}
            </button>
          )
        })}
      </nav>

      {/* 右:实体页(页头 + 内容) */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="mb-3 flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1">
          <h2 className="text-[18px] font-semibold text-ink">{current?.label}</h2>
          <span className="text-[13px] text-ink-mute">{current?.desc}</span>
          {scopedView && (
            <Badge tone="info" className="ml-auto">
              {t('admin.scoped_badge')}
            </Badge>
          )}
        </header>

        <div className="flex min-h-0 flex-1 flex-col">
          {section === 'members' && (
            <MembersTab
              departments={departments}
              roles={roles}
              canManage={canManageUsers}
              scoped={scopedView}
              onChanged={reloadMeta}
            />
          )}
          {section === 'teams' && (
            <DepartmentsTab
              departments={departments}
              canManage={canManageDept}
              onChanged={reloadMeta}
            />
          )}
          {section === 'roles' && canViewOrg && (
            <RolesTab
              roles={roles}
              permissions={permissions}
              canManage={canManageRoles}
              onChanged={reloadMeta}
            />
          )}
          {section === 'approvals' && canApprove && (
            <ApprovalsTab
              departments={departments}
              roles={roles}
              scoped={scopedView}
              onChanged={reloadMeta}
            />
          )}
        </div>
      </div>
    </div>
  )
}
