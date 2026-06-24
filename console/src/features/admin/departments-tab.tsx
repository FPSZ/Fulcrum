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
      toast.success('已删除部门')
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  const submit = async () => {
    if (!dialog) return
    if (!dialog.name.trim()) return toast.error('请填写部门名称')
    setBusy(true)
    try {
      if (dialog.mode === 'create') {
        await createDepartment({ name: dialog.name.trim(), parent_id: dialog.parent_id })
        toast.success('部门已创建')
      } else {
        await updateDepartment(dialog.id!, {
          name: dialog.name.trim(),
          parent_id: dialog.parent_id,
        })
        toast.success('已保存')
      }
      setDialog(null)
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setBusy(false)
    }
  }

  const parentOptions = [
    { value: NONE, label: '顶层(无上级)' },
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
            新建部门
          </Button>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto rounded-[12px] border border-line">
        {rows.length === 0 ? (
          <EmptyState icon={Building2} title="暂无部门" hint="点击右上角新建部门,搭建组织架构。" />
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
                <span className="font-data text-[13px] text-ink-mute">{d.member_count} 人</span>
                <IconButton label="团队成员" onClick={() => setTeamFor(d)}>
                  <Users className="h-[15px] w-[15px]" />
                </IconButton>
                {canManage && (
                  <div className="flex items-center gap-0.5 opacity-100 transition-opacity md:opacity-0 md:group-hover:opacity-100">
                    <IconButton label="添加子部门" onClick={() => openCreate(d.id)}>
                      <Plus className="h-[15px] w-[15px]" />
                    </IconButton>
                    <IconButton label="编辑" onClick={() => openEdit(d)}>
                      <Pencil className="h-[15px] w-[15px]" />
                    </IconButton>
                    <IconButton label="删除" className="hover:text-crit" onClick={() => remove(d)}>
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
          title={dialog.mode === 'create' ? '新建部门' : '编辑部门'}
          widthClassName="max-w-md"
          footer={
            <>
              <Button variant="ghost" onClick={() => setDialog(null)}>取消</Button>
              <Button variant="primary" onClick={submit} disabled={busy}>
                {dialog.mode === 'create' ? '创建' : '保存'}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <label className="block">
              <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">部门名称</span>
              <Input
                value={dialog.name}
                autoFocus
                onChange={(e) => setDialog({ ...dialog, name: e.target.value })}
                placeholder="如 应急响应组"
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">上级部门</span>
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
        <TeamMembersDialog team={teamFor} canManage={canManage} onClose={() => setTeamFor(null)} />
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
      toast.error(e instanceof Error ? e.message : '加载团队成员失败')
    }
  }, [team.id])

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
      toast.error(e instanceof Error ? e.message : '操作失败')
    } finally {
      setBusy(false)
    }
  }

  const add = () =>
    addId &&
    guard(async () => {
      await addTeamMember(team.id, { user_id: Number(addId) })
      setAddId('')
      toast.success('已加入团队')
    })
  const remove = (uid: number) => guard(() => removeTeamMember(team.id, uid))
  const toggleLead = (m: Membership) =>
    guard(() =>
      addTeamMember(team.id, { user_id: m.user_id, team_role: m.team_role, is_lead: !m.is_lead }),
    )

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`团队成员 · ${team.name}`}>
      <div className="space-y-3">
        {members.length === 0 ? (
          <p className="rounded-lg bg-surface-2 px-3 py-6 text-center text-[13.5px] text-ink-3">
            该团队还没有成员
          </p>
        ) : (
          <ul className="divide-y divide-line rounded-[10px] border border-line">
            {members.map((m) => (
              <li key={m.user_id} className="flex items-center gap-2.5 px-3 py-2.5">
                <span className="min-w-0 flex-1 truncate text-[14px] text-ink">{nameOf(m.user_id)}</span>
                {m.is_lead && (
                  <Badge tone="info">
                    <ShieldCheck className="h-3 w-3" /> 负责人
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
                      {m.is_lead ? '取消负责人' : '设为负责人'}
                    </button>
                    <IconButton
                      label="移出团队"
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
                { value: '', label: addable.length ? '选择成员加入…' : '无可加入的成员' },
                ...addable.map((u) => ({ value: String(u.id), label: u.display_name })),
              ]}
              className="flex-1"
            />
            <Button variant="primary" onClick={add} disabled={busy || !addId}>
              <UserPlus className="h-4 w-4" />
              加入
            </Button>
          </div>
        )}
      </div>
    </Dialog>
  )
}
