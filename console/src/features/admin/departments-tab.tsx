import { useCallback, useEffect, useState } from 'react'
import {
  Building2,
  FolderPlus,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
  X,
} from 'lucide-react'
import { Badge, Button, Dialog, EmptyState, IconButton, Input, Select, toast } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/lib/i18n'
import { useAuth } from '@/lib/auth'
import {
  addTeamMember,
  createDepartment,
  deleteDepartment,
  listMembers,
  listTeamMembers,
  removeTeamMember,
  updateDepartment,
  type Department,
  type Member,
  type Membership,
} from '@/lib/admin'
import { buildTree, flattenTree } from './shared'

const NONE = '0' // 顶层(无上级)

interface Props {
  departments: Department[]
  canManage: boolean
  onChanged: () => void
}

interface DialogState {
  mode: 'create' | 'edit'
  id?: number
  name: string
  parent_id: number | null
}

export function DepartmentsTab({ departments, canManage, onChanged }: Props) {
  const { t } = useTranslation()
  const { canManageTeam } = useAuth()
  const rows = flattenTree(buildTree(departments))
  const [dialog, setDialog] = useState<DialogState | null>(null)
  const [teamFor, setTeamFor] = useState<Department | null>(null)
  const [busy, setBusy] = useState(false)

  const openCreate = (parent_id: number | null) =>
    setDialog({ mode: 'create', name: '', parent_id })
  const openEdit = (d: Department) =>
    setDialog({ mode: 'edit', id: d.id, name: d.name, parent_id: d.parent_id })

  const remove = async (d: Department) => {
    try {
      await deleteDepartment(d.id)
      toast.success(t('admin.dept.deleted'))
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.dept.delete_failed'))
    }
  }

  const submit = async () => {
    if (!dialog) return
    if (!dialog.name.trim()) return toast.error(t('admin.dept.require_name'))
    setBusy(true)
    try {
      if (dialog.mode === 'create') {
        await createDepartment({ name: dialog.name.trim(), parent_id: dialog.parent_id })
        toast.success(t('admin.dept.created'))
      } else {
        await updateDepartment(dialog.id!, {
          name: dialog.name.trim(),
          parent_id: dialog.parent_id,
        })
        toast.success(t('admin.member_form.saved'))
      }
      setDialog(null)
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.member_form.save_failed'))
    } finally {
      setBusy(false)
    }
  }

  const parentOptions = [
    { value: NONE, label: t('admin.dept.top_level') },
    // 编辑时排除自身,避免选自己当父级(成环由后端兜底,这里先做体验)
    ...departments
      .filter((d) => dialog?.mode !== 'edit' || d.id !== dialog?.id)
      .map((d) => ({ value: String(d.id), label: d.name })),
  ]

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {canManage && (
        <div className="mb-3 flex">
          <Button variant="primary" className="ml-auto" onClick={() => openCreate(null)}>
            <FolderPlus className="h-4 w-4" />
            {t('admin.dept.new')}
          </Button>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto rounded-[12px] border border-line">
        {rows.length === 0 ? (
          <EmptyState
            icon={Building2}
            title={t('admin.dept.empty.title')}
            hint={t('admin.dept.empty.hint')}
          />
        ) : (
          <ul className="divide-y divide-line">
            {rows.map((d) => (
              <li
                key={d.id}
                className="group flex items-center gap-2 px-3 py-2.5 transition-colors hover:bg-surface-2/60"
                style={{ paddingLeft: `${d.depth * 22 + 12}px` }}
              >
                <Building2 className="h-4 w-4 shrink-0 text-ink-mute" strokeWidth={1.8} />
                <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-ink">
                  {d.name}
                </span>
                <span className="font-data text-[13px] text-ink-mute">
                  {t('admin.dept.member_unit', { count: d.member_count })}
                </span>
                <IconButton label={t('admin.dept.team_members')} onClick={() => setTeamFor(d)}>
                  <Users className="h-[15px] w-[15px]" />
                </IconButton>
                {canManage && (
                  <div className="flex items-center gap-0.5 opacity-100 transition-opacity md:opacity-0 md:group-hover:opacity-100">
                    <IconButton label={t('admin.dept.add_child')} onClick={() => openCreate(d.id)}>
                      <Plus className="h-[15px] w-[15px]" />
                    </IconButton>
                    <IconButton label={t('common.edit')} onClick={() => openEdit(d)}>
                      <Pencil className="h-[15px] w-[15px]" />
                    </IconButton>
                    <IconButton label={t('common.delete')} className="hover:text-crit" onClick={() => remove(d)}>
                      <Trash2 className="h-[15px] w-[15px]" />
                    </IconButton>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {dialog && (
        <Dialog
          open
          onOpenChange={(o) => !o && setDialog(null)}
          title={dialog.mode === 'create' ? t('admin.dept.new') : t('admin.dept.edit')}
          widthClassName="max-w-md"
          footer={
            <>
              <Button variant="ghost" onClick={() => setDialog(null)}>{t('common.cancel')}</Button>
              <Button variant="primary" onClick={submit} disabled={busy}>
                {dialog.mode === 'create' ? t('admin.member_form.create') : t('common.save')}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <label className="block">
              <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">{t('admin.dept.name')}</span>
              <Input
                value={dialog.name}
                autoFocus
                onChange={(e) => setDialog({ ...dialog, name: e.target.value })}
                placeholder={t('admin.dept.name_ph')}
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">{t('admin.dept.parent')}</span>
              <Select
                value={dialog.parent_id == null ? NONE : String(dialog.parent_id)}
                onValueChange={(v) =>
                  setDialog({ ...dialog, parent_id: v === NONE ? null : Number(v) })
                }
                options={parentOptions}
                className={cn('w-full')}
              />
            </label>
          </div>
        </Dialog>
      )}

      {teamFor && (
        <TeamMembersDialog
          team={teamFor}
          canManage={canManageTeam(teamFor.id)}
          onClose={() => setTeamFor(null)}
        />
      )}
    </div>
  )
}

/** 团队成员面板:团队 = 带「负责人 + 成员」的实体(plan/13 §10)。负责人/组织管理员可增删、设负责人。 */
function TeamMembersDialog({
  team,
  canManage,
  onClose,
}: {
  team: Department
  canManage: boolean
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [members, setMembers] = useState<Membership[]>([])
  const [all, setAll] = useState<Member[]>([])
  const [addId, setAddId] = useState('')
  const [busy, setBusy] = useState(false)

  const reload = useCallback(async () => {
    try {
      const [m, a] = await Promise.all([listTeamMembers(team.id), listMembers()])
      setMembers(m)
      setAll(a)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.team.load_failed'))
    }
  }, [t, team.id])

  useEffect(() => {
    void reload()
  }, [reload])

  const nameOf = (uid: number) => all.find((u) => u.id === uid)?.display_name ?? `#${uid}`
  const inTeam = new Set(members.map((m) => m.user_id))
  const addable = all.filter((u) => !inTeam.has(u.id) && u.status === 'active')

  const guard = async (fn: () => Promise<unknown>) => {
    setBusy(true)
    try {
      await fn()
      await reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.members.op_failed'))
    } finally {
      setBusy(false)
    }
  }

  const add = () =>
    addId &&
    guard(async () => {
      await addTeamMember(team.id, { user_id: Number(addId) })
      setAddId('')
      toast.success(t('admin.team.joined'))
    })
  const remove = (uid: number) => guard(() => removeTeamMember(team.id, uid))
  const toggleLead = (m: Membership) =>
    guard(() =>
      addTeamMember(team.id, { user_id: m.user_id, team_role: m.team_role, is_lead: !m.is_lead }),
    )

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={t('admin.team.title', { name: team.name })}>
      <div className="space-y-3">
        {members.length === 0 ? (
          <p className="rounded-lg bg-surface-2 px-3 py-6 text-center text-[13.5px] text-ink-3">
            {t('admin.team.empty')}
          </p>
        ) : (
          <ul className="divide-y divide-line rounded-[10px] border border-line">
            {members.map((m) => (
              <li key={m.user_id} className="flex items-center gap-2.5 px-3 py-2.5">
                <span className="min-w-0 flex-1 truncate text-[14px] text-ink">{nameOf(m.user_id)}</span>
                {m.is_lead && (
                  <Badge tone="info">
                    <ShieldCheck className="h-3 w-3" /> {t('admin.team.lead')}
                  </Badge>
                )}
                {canManage && (
                  <>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => toggleLead(m)}
                      className="focus-ring rounded-md px-2 py-1 text-[12.5px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink-2 disabled:opacity-50"
                    >
                      {m.is_lead ? t('admin.team.unset_lead') : t('admin.team.set_lead')}
                    </button>
                    <IconButton
                      label={t('admin.team.remove')}
                      className="hover:text-crit"
                      onClick={() => remove(m.user_id)}
                    >
                      <X className="h-[15px] w-[15px]" />
                    </IconButton>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}

        {canManage && (
          <div className="flex items-center gap-2">
            <Select
              value={addId}
              onValueChange={setAddId}
              options={[
                { value: '', label: addable.length ? t('admin.team.add_ph') : t('admin.team.add_none') },
                ...addable.map((u) => ({ value: String(u.id), label: u.display_name })),
              ]}
              className="flex-1"
            />
            <Button variant="primary" onClick={add} disabled={busy || !addId}>
              <UserPlus className="h-4 w-4" />
              {t('admin.team.add')}
            </Button>
          </div>
        )}
      </div>
    </Dialog>
  )
}
