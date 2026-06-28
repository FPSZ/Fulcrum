import { useCallback, useEffect, useMemo, useState } from 'react'
import { KeyRound, Pencil, Power, Search, UserPlus, Users } from 'lucide-react'
import {
  Avatar,
  Button,
  Dialog,
  EmptyState,
  IconButton,
  Input,
  Segmented,
  Select,
  toast,
} from '@/components/ui'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/lib/i18n'
import {
  createMember,
  listMembers,
  resetMemberPassword,
  setMemberStatus,
  updateMember,
  type Department,
  type Member,
  type Role,
  type UserStatus,
} from '@/lib/admin'
import {
  StatusBadge,
  TempPasswordDialog,
  buildTree,
  deptName,
  flattenTree,
  fmtTime,
  roleName,
} from './shared'

const NONE = '0' // Select 哨兵:未分配部门/角色

interface Props {
  departments: Department[]
  roles: Role[]
  canManage: boolean
  /** 纯团队负责人视图:成员列表后端已按本团队行级过滤,隐藏组织架构树筛选 */
  scoped?: boolean
  onChanged: () => void
}

export function MembersTab({ departments, roles, canManage, scoped = false, onChanged }: Props) {
  const { t } = useTranslation()
  const [members, setMembers] = useState<Member[]>([])
  const [loading, setLoading] = useState(true)
  const [deptFilter, setDeptFilter] = useState<number | null>(null)
  const [statusFilter, setStatusFilter] = useState<'all' | UserStatus>('all')
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState<Member | null>(null)
  const [creating, setCreating] = useState(false)
  const [temp, setTemp] = useState<{ username: string; password: string } | null>(null)

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const data = await listMembers({
        department_id: deptFilter,
        status: statusFilter === 'all' ? undefined : statusFilter,
        search: search.trim() || undefined,
      })
      setMembers(data)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.members.load_failed'))
    } finally {
      setLoading(false)
    }
  }, [t, deptFilter, statusFilter, search])

  useEffect(() => {
    void reload()
  }, [reload])

  const tree = useMemo(() => flattenTree(buildTree(departments)), [departments])
  const refreshAll = () => {
    void reload()
    onChanged()
  }

  const toggleStatus = async (m: Member) => {
    try {
      await setMemberStatus(m.id, m.status === 'active' ? 'disabled' : 'active')
      toast.success(m.status === 'active' ? t('admin.members.disabled') : t('admin.members.enabled'))
      refreshAll()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.members.op_failed'))
    }
  }

  const reset = async (m: Member) => {
    try {
      const r = await resetMemberPassword(m.id)
      if (r.temp_password) setTemp({ username: m.username, password: r.temp_password })
      else toast.success(t('admin.members.pw_reset'))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.members.op_failed'))
    }
  }

  return (
    <div className="flex min-h-0 flex-1 gap-4">
      {/* 左:组织架构树(点击筛选);移动端隐藏,表格占满;团队负责人视图不展示(已限本团队) */}
      {!scoped && (
        <aside className="hidden w-60 shrink-0 flex-col gap-1 overflow-y-auto rounded-[12px] border border-line bg-surface/60 p-2 md:flex">
          <TreeItem label={t('admin.members.all')} active={deptFilter === null} depth={0}
            onClick={() => setDeptFilter(null)} />
          {tree.map((d) => (
            <TreeItem
              key={d.id}
              label={d.name}
              count={d.member_count}
              depth={d.depth}
              active={deptFilter === d.id}
              onClick={() => setDeptFilter(d.id)}
            />
          ))}
        </aside>
      )}

      {/* 右:工具条 + 成员表 */}
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-mute" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('admin.members.search')}
              className="w-[230px] pl-8"
            />
          </div>
          <Segmented
            value={statusFilter}
            onValueChange={(v) => setStatusFilter(v as 'all' | UserStatus)}
            items={[
              { value: 'all', label: t('admin.members.filter.all') },
              { value: 'active', label: t('admin.members.filter.active') },
              { value: 'disabled', label: t('admin.members.filter.disabled') },
            ]}
          />
          {canManage && (
            <Button variant="primary" className="ml-auto" onClick={() => setCreating(true)}>
              <UserPlus className="h-4 w-4" />
              {t('admin.members.add')}
            </Button>
          )}
        </div>

        <div className="min-h-0 flex-1 overflow-auto rounded-[12px] border border-line">
          <table className="hidden w-full border-collapse text-[14px] md:table">
            <thead className="sticky top-0 z-[1] bg-subtle text-[13px] text-ink-3">
              <tr className="[&>th]:px-3 [&>th]:py-2.5 [&>th]:text-left [&>th]:font-medium">
                <th>{t('admin.members.col.member')}</th>
                <th>{t('admin.members.col.dept')}</th>
                <th>{t('admin.members.col.role')}</th>
                <th>{t('admin.members.col.status')}</th>
                <th>{t('admin.members.col.last_login')}</th>
                {canManage && <th className="text-right">{t('admin.members.col.actions')}</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {members.map((m) => (
                <tr key={m.id} className="transition-colors hover:bg-surface-2/60">
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-2.5">
                      <Avatar fallback={m.display_name.slice(0, 1)} className="h-8 w-8 rounded-[9px]" />
                      <div className="min-w-0">
                        <div className="truncate font-medium text-ink">
                          {m.display_name}
                          {m.title && <span className="ml-1.5 text-[12.5px] font-normal text-ink-mute">{m.title}</span>}
                        </div>
                        <div className="truncate font-data text-[12.5px] text-ink-mute">{m.username}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-ink-2">{deptName(departments, m.department_id)}</td>
                  <td className="px-3 py-2.5 text-ink-2">{roleName(roles, m.role_id)}</td>
                  <td className="px-3 py-2.5"><StatusBadge status={m.status} /></td>
                  <td className="px-3 py-2.5 font-data text-[13px] text-ink-3">{fmtTime(m.last_login_at)}</td>
                  {canManage && (
                    <td className="px-3 py-2.5">
                      <div className="flex items-center justify-end gap-1">
                        <IconButton label={t('common.edit')} onClick={() => setEditing(m)}>
                          <Pencil className="h-[15px] w-[15px]" />
                        </IconButton>
                        <IconButton label={t('admin.members.reset_pw')} onClick={() => reset(m)}>
                          <KeyRound className="h-[15px] w-[15px]" />
                        </IconButton>
                        <IconButton
                          label={m.status === 'active' ? t('admin.members.disable') : t('admin.members.enable')}
                          onClick={() => toggleStatus(m)}
                          className={m.status === 'active' ? 'hover:text-crit' : 'hover:text-ok'}
                        >
                          <Power className="h-[15px] w-[15px]" />
                        </IconButton>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>

          {/* 移动端:成员卡片流(不横滑) */}
          <div className="divide-y divide-line md:hidden">
            {members.map((m) => (
              <div key={m.id} className="flex items-start gap-3 px-3 py-3">
                <Avatar fallback={m.display_name.slice(0, 1)} className="mt-0.5 h-9 w-9 shrink-0 rounded-[10px]" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium text-ink">{m.display_name}</span>
                    {m.title && <span className="shrink-0 text-[12px] text-ink-mute">{m.title}</span>}
                  </div>
                  <div className="truncate font-data text-[12px] text-ink-mute">{m.username}</div>
                  <div className="mt-1 flex items-center gap-2 text-[12.5px] text-ink-2">
                    <StatusBadge status={m.status} />
                    <span className="truncate">
                      {deptName(departments, m.department_id)} · {roleName(roles, m.role_id)}
                    </span>
                  </div>
                </div>
                {canManage && (
                  <div className="flex shrink-0 items-center gap-0.5">
                    <IconButton label={t('common.edit')} onClick={() => setEditing(m)}>
                      <Pencil className="h-[15px] w-[15px]" />
                    </IconButton>
                    <IconButton label={t('admin.members.reset_pw')} onClick={() => reset(m)}>
                      <KeyRound className="h-[15px] w-[15px]" />
                    </IconButton>
                    <IconButton
                      label={m.status === 'active' ? t('admin.members.disable') : t('admin.members.enable')}
                      onClick={() => toggleStatus(m)}
                      className={m.status === 'active' ? 'hover:text-crit' : 'hover:text-ok'}
                    >
                      <Power className="h-[15px] w-[15px]" />
                    </IconButton>
                  </div>
                )}
              </div>
            ))}
          </div>

          {!loading && members.length === 0 && (
            <EmptyState
              icon={Users}
              title={t('admin.members.empty.title')}
              hint={t('admin.members.empty.hint')}
            />
          )}
        </div>
      </div>

      {(creating || editing) && (
        <MemberDialog
          open
          member={editing}
          departments={departments}
          roles={roles}
          onClose={() => {
            setCreating(false)
            setEditing(null)
          }}
          onCreated={(username, password) => {
            if (password) setTemp({ username, password })
            refreshAll()
          }}
          onSaved={refreshAll}
        />
      )}
      {temp && (
        <TempPasswordDialog
          open
          onClose={() => setTemp(null)}
          username={temp.username}
          password={temp.password}
        />
      )}
    </div>
  )
}

function TreeItem({
  label,
  count,
  depth,
  active,
  onClick,
}: {
  label: string
  count?: number
  depth: number
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{ paddingLeft: `${depth * 14 + 10}px` }}
      className={cn(
        'focus-ring flex h-8 w-full items-center gap-2 rounded-[8px] pr-2 text-left text-[14px] transition-colors',
        active ? 'bg-accent/10 font-medium text-accent-ink' : 'text-ink-2 hover:bg-surface-2',
      )}
    >
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {typeof count === 'number' && count > 0 && (
        <span className="font-data text-[12.5px] text-ink-mute">{count}</span>
      )}
    </button>
  )
}

/** 新增 / 编辑成员表单 */
function MemberDialog({
  open,
  member,
  departments,
  roles,
  onClose,
  onCreated,
  onSaved,
}: {
  open: boolean
  member: Member | null
  departments: Department[]
  roles: Role[]
  onClose: () => void
  onCreated: (username: string, password: string | null) => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const editMode = member !== null
  const [form, setForm] = useState({
    username: member?.username ?? '',
    display_name: member?.display_name ?? '',
    employee_no: member?.employee_no ?? '',
    email: member?.email ?? '',
    phone: member?.phone ?? '',
    title: member?.title ?? '',
    department_id: member?.department_id ?? null,
    role_id: member?.role_id ?? null,
  })
  const [busy, setBusy] = useState(false)
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) =>
    setForm((f) => ({ ...f, [k]: v }))

  const deptOptions = [
    { value: NONE, label: t('admin.unassigned_dept') },
    ...departments.map((d) => ({ value: String(d.id), label: d.name })),
  ]
  const roleOptions = [
    { value: NONE, label: t('admin.unassigned_role') },
    ...roles.map((r) => ({ value: String(r.id), label: r.name })),
  ]

  const submit = async () => {
    if (!form.display_name.trim() || (!editMode && !form.username.trim())) {
      toast.error(t('admin.member_form.require_name_account'))
      return
    }
    setBusy(true)
    try {
      if (editMode) {
        await updateMember(member.id, {
          display_name: form.display_name,
          employee_no: form.employee_no,
          email: form.email,
          phone: form.phone,
          title: form.title,
          department_id: form.department_id,
          role_id: form.role_id,
        })
        toast.success(t('admin.member_form.saved'))
        onSaved()
      } else {
        const r = await createMember({
          username: form.username,
          display_name: form.display_name,
          employee_no: form.employee_no,
          email: form.email,
          phone: form.phone,
          title: form.title,
          department_id: form.department_id,
          role_id: form.role_id,
        })
        toast.success(t('admin.member_form.created'))
        onCreated(r.user.username, r.temp_password)
      }
      onClose()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.member_form.save_failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={editMode ? t('admin.member_form.edit') : t('admin.member_form.new')}
      description={editMode ? undefined : t('admin.member_form.new_desc')}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={submit} disabled={busy}>
            {editMode ? t('common.save') : t('admin.member_form.create')}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <FormField label={t('admin.member_form.name')} required>
          <Input value={form.display_name} onChange={(e) => set('display_name', e.target.value)} />
        </FormField>
        <FormField label={t('admin.member_form.account')} required>
          <Input
            value={form.username}
            onChange={(e) => set('username', e.target.value)}
            disabled={editMode}
            placeholder={t('admin.member_form.account_ph')}
          />
        </FormField>
        <FormField label={t('admin.member_form.employee_no')}>
          <Input value={form.employee_no} onChange={(e) => set('employee_no', e.target.value)} />
        </FormField>
        <FormField label={t('admin.member_form.title')}>
          <Input value={form.title} onChange={(e) => set('title', e.target.value)} placeholder={t('admin.member_form.title_ph')} />
        </FormField>
        <FormField label={t('admin.member_form.email')}>
          <Input value={form.email} onChange={(e) => set('email', e.target.value)} />
        </FormField>
        <FormField label={t('admin.member_form.phone')}>
          <Input value={form.phone} onChange={(e) => set('phone', e.target.value)} />
        </FormField>
        <FormField label={t('admin.member_form.dept')}>
          <Select
            value={form.department_id == null ? NONE : String(form.department_id)}
            onValueChange={(v) => set('department_id', v === NONE ? null : Number(v))}
            options={deptOptions}
            className="w-full"
          />
        </FormField>
        <FormField label={t('admin.member_form.role')}>
          <Select
            value={form.role_id == null ? NONE : String(form.role_id)}
            onValueChange={(v) => set('role_id', v === NONE ? null : Number(v))}
            options={roleOptions}
            className="w-full"
          />
        </FormField>
      </div>
    </Dialog>
  )
}

function FormField({
  label,
  required,
  children,
}: {
  label: string
  required?: boolean
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">
        {label}
        {required && <span className="ml-0.5 text-crit">*</span>}
      </span>
      {children}
    </label>
  )
}
