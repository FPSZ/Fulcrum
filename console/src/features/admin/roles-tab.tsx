import { useCallback, useEffect, useMemo, useState } from 'react'
import { Check, Eye, Pencil, Plus, Save, Shield, Trash2, Users } from 'lucide-react'
import {
  Avatar,
  Button,
  Dialog,
  EmptyState,
  IconButton,
  Input,
  toast,
} from '@/components/ui'
import { cn } from '@/lib/utils'
import {
  createRole,
  deleteRole,
  listMembers,
  updateRole,
  type Member,
  type PermissionDef,
  type Role,
} from '@/lib/admin'
import { StatusBadge } from './shared'

interface Props {
  roles: Role[]
  permissions: PermissionDef[]
  canManage: boolean
  onChanged: () => void
}

const sameSet = (a: Set<string>, b: Iterable<string>): boolean => {
  const bs = new Set(b)
  if (a.size !== bs.size) return false
  for (const x of a) if (!bs.has(x)) return false
  return true
}

/** 一个能力域:把同 capability 的「看(read)/改(write)」合成一行,单点用 actionKey。 */
interface Cap {
  capability: string
  cap_label: string
  readKey?: string // access==='read' 的权限点(只读)
  writeKey?: string // access==='write' 的权限点(读写需连带 readKey)
  actionKey?: string // access==='action' 的单点(无看改之分,如审批)
}

/** 影响面分类顺序(与后端 group 对齐):末两组「成员与权限/系统配置」最敏感。 */
const GROUP_ORDER = ['监测', '管控', '取证', '成员与权限', '系统配置']

/** 容错:旧后端未带 capability/cap_label/access 时,从 key 后缀派生(.view→read / .manage|.handle|.run→write)。 */
function metaOf(p: PermissionDef): { capability: string; cap_label: string; access: PermissionDef['access'] } {
  if (p.capability && p.access) {
    return { capability: p.capability, cap_label: p.cap_label || p.label, access: p.access }
  }
  const [dom, act] = p.key.split('.')
  const access: PermissionDef['access'] =
    act === 'view' ? 'read' : ['manage', 'handle', 'run'].includes(act) ? 'write' : 'action'
  return { capability: `${dom}.${access === 'action' ? act : ''}`, cap_label: p.label, access }
}

/** 权限点目录 → 按影响面分组、组内按能力域合成(保留出现顺序)。 */
function buildGroups(perms: PermissionDef[]): { group: string; caps: Cap[] }[] {
  const byGroup = new Map<string, Map<string, Cap>>()
  for (const p of perms) {
    const m = metaOf(p)
    if (!byGroup.has(p.group)) byGroup.set(p.group, new Map())
    const caps = byGroup.get(p.group)!
    const cap: Cap = caps.get(m.capability) ?? { capability: m.capability, cap_label: m.cap_label }
    if (m.access === 'read') cap.readKey = p.key
    else if (m.access === 'write') cap.writeKey = p.key
    else cap.actionKey = p.key
    caps.set(m.capability, cap)
  }
  const known = GROUP_ORDER.filter((g) => byGroup.has(g))
  const extra = [...byGroup.keys()].filter((g) => !GROUP_ORDER.includes(g)) // 兜底:未知组排末尾
  return [...known, ...extra].map((g) => ({ group: g, caps: [...byGroup.get(g)!.values()] }))
}

/** 某能力域在当前授权集下的级别:0 无 / 1 只读 / 2 读写(action 用 2 表示「已授权」)。 */
function levelOf(cap: Cap, granted: Set<string>): 0 | 1 | 2 {
  if (cap.actionKey) return granted.has(cap.actionKey) ? 2 : 0
  if (cap.writeKey && granted.has(cap.writeKey)) return 2
  if (cap.readKey && granted.has(cap.readKey)) return 1
  return 0
}

/** 点击循环:无→只读→读写→无(只读/只写能力则二态);返回新授权集。 */
function cycleCap(cap: Cap, granted: Set<string>): Set<string> {
  const next = new Set(granted)
  if (cap.actionKey) {
    if (next.has(cap.actionKey)) next.delete(cap.actionKey)
    else next.add(cap.actionKey)
    return next
  }
  const lvl = levelOf(cap, granted)
  if (cap.readKey) next.delete(cap.readKey)
  if (cap.writeKey) next.delete(cap.writeKey)
  const hasRead = !!cap.readKey
  const hasWrite = !!cap.writeKey
  if (hasRead && hasWrite) {
    const target = (lvl + 1) % 3 // 0→1→2→0
    if (target >= 1) next.add(cap.readKey!)
    if (target === 2) next.add(cap.writeKey!) // 读写连带 read,保证能看到才改
  } else if (hasRead) {
    if (lvl === 0) next.add(cap.readKey!) // 二态:无↔只读
  } else if (hasWrite) {
    if (lvl === 0) next.add(cap.writeKey!) // 二态:无↔读写(管理类无只读)
  }
  return next
}

export function RolesTab({ roles, permissions, canManage, onChanged }: Props) {
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [memberId, setMemberId] = useState<number | null>(null)
  const [members, setMembers] = useState<Member[]>([])
  const [loadingMembers, setLoadingMembers] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [editMeta, setEditMeta] = useState<Role | null>(null)

  // 选中角色:优先用户选择,否则第一项
  const selected = useMemo(
    () => roles.find((r) => r.id === selectedId) ?? roles[0] ?? null,
    [roles, selectedId],
  )
  const selectedMember = useMemo(
    () => members.find((m) => m.id === memberId) ?? null,
    [members, memberId],
  )

  const loadMembers = useCallback(() => {
    if (!selected) {
      setMembers([])
      return
    }
    setLoadingMembers(true)
    listMembers({ role_id: selected.id })
      .then(setMembers)
      .catch((e) => toast.error(e instanceof Error ? e.message : '加载成员失败'))
      .finally(() => setLoadingMembers(false))
  }, [selected])

  // 切换角色 → 重新拉成员并清掉成员选择
  useEffect(() => {
    setMemberId(null)
    loadMembers()
  }, [loadMembers])

  const groups = useMemo(() => buildGroups(permissions), [permissions])

  const pickRole = (id: number) => {
    setSelectedId(id)
    setMemberId(null)
  }

  const remove = async (r: Role) => {
    try {
      await deleteRole(r.id)
      toast.success('已删除角色')
      if (selectedId === r.id) setSelectedId(null)
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto pb-1 lg:flex-row lg:overflow-visible">
      {/* ── 左:角色列表(首项 = 新建角色) ── */}
      <aside className="flex max-h-[40vh] w-full shrink-0 flex-col overflow-hidden rounded-[12px] border border-line bg-surface/60 lg:max-h-none lg:w-72">
        <div className="min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
          {canManage && (
            <button
              type="button"
              onClick={() => setCreateOpen(true)}
              className="focus-ring flex min-h-[52px] w-full items-center gap-2.5 rounded-[10px] border border-dashed border-accent/40 px-2.5 py-2 text-left text-accent transition-colors hover:bg-accent/8"
            >
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-[9px] bg-accent/10 text-accent">
                <Plus className="h-[18px] w-[18px]" strokeWidth={2.1} />
              </span>
              <span className="text-[14.5px] font-semibold">新建角色</span>
            </button>
          )}
          {roles.map((r) => {
            const active = selected?.id === r.id
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => pickRole(r.id)}
                className={cn(
                  'focus-ring flex w-full items-center gap-2.5 rounded-[10px] border px-2.5 py-2 text-left transition-colors',
                  active
                    ? 'border-accent/30 bg-accent/10'
                    : 'border-transparent hover:border-line-2 hover:bg-surface-2',
                )}
              >
                <span
                  className={cn(
                    'grid h-8 w-8 shrink-0 place-items-center rounded-[9px]',
                    active ? 'bg-accent text-white' : 'bg-accent/10 text-accent',
                  )}
                >
                  <Shield className="h-[17px] w-[17px]" strokeWidth={1.9} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={cn(
                        'min-w-0 flex-1 truncate text-[14.5px] font-semibold',
                        active ? 'text-accent-ink' : 'text-ink',
                      )}
                    >
                      {r.name}
                    </span>
                    {r.is_system && (
                      <span className="shrink-0 rounded-full bg-subtle px-1.5 py-0.5 text-[11px] font-medium text-ink-mute">
                        内置
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-[12px] text-ink-mute">
                    <span>{r.permissions.length} 权限</span>
                    <span>·</span>
                    <span>{r.member_count} 人</span>
                  </div>
                </div>
              </button>
            )
          })}
          {roles.length === 0 && (
            <EmptyState icon={Shield} title="暂无角色" hint="新建或恢复一个角色。" />
          )}
        </div>
      </aside>

      {/* ── 中:角色权限项 + 成员(可点选) ── */}
      <aside className="flex max-h-[40vh] w-full shrink-0 flex-col overflow-hidden rounded-[12px] border border-line bg-surface lg:max-h-none lg:w-72">
        {selected ? (
          <>
            <div className="flex items-center gap-1.5 border-b border-line px-3 py-2.5 text-[12px] text-ink-mute">
              <Users className="h-[14px] w-[14px]" />
              成员 <span className="font-data font-semibold text-ink-2">{members.length}</span>
            </div>

            <div className="min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
              {members.map((m) => {
                const active = memberId === m.id
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => setMemberId(active ? null : m.id)}
                    className={cn(
                      'focus-ring flex w-full items-center gap-2.5 rounded-[9px] border px-2 py-1.5 text-left transition-colors',
                      active
                        ? 'border-accent/30 bg-accent/10'
                        : 'border-transparent hover:bg-surface-2',
                    )}
                  >
                    <Avatar fallback={m.display_name.slice(0, 1)} className="h-8 w-8 rounded-[9px]" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[14px] font-medium text-ink">{m.display_name}</div>
                      <div className="truncate font-data text-[12px] text-ink-mute">{m.username}</div>
                    </div>
                    <StatusBadge status={m.status} />
                  </button>
                )
              })}
              {!loadingMembers && members.length === 0 && (
                <EmptyState icon={Users} title="暂无成员" hint="还没有成员分配到该角色。" />
              )}
            </div>
          </>
        ) : (
          <div className="grid flex-1 place-items-center">
            <EmptyState icon={Shield} title="未选择角色" hint="从左侧选择一个角色。" />
          </div>
        )}
      </aside>

      {/* ── 右:权限(角色可编辑 / 成员只读继承) ── */}
      <RolePermissions
        role={selected}
        member={selectedMember}
        groups={groups}
        canManage={canManage}
        onChanged={onChanged}
        onEditMeta={() => selected && setEditMeta(selected)}
        onDelete={() => selected && void remove(selected)}
      />

      {(createOpen || editMeta) && (
        <RoleMetaDialog
          role={editMeta}
          onClose={() => {
            setCreateOpen(false)
            setEditMeta(null)
          }}
          onSaved={(id) => {
            if (id) pickRole(id)
            onChanged()
          }}
        />
      )}
    </div>
  )
}

/** 右栏:角色权限(自定义可就地编辑);选中成员时只读展示其继承的角色权限 */
function RolePermissions({
  role,
  member,
  groups,
  canManage,
  onChanged,
  onEditMeta,
  onDelete,
}: {
  role: Role | null
  member: Member | null
  groups: { group: string; caps: Cap[] }[]
  canManage: boolean
  onChanged: () => void
  onEditMeta: () => void
  onDelete: () => void
}) {
  const [draft, setDraft] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setDraft(new Set(role?.permissions ?? []))
  }, [role])

  if (!role) {
    return (
      <div className="grid flex-1 place-items-center rounded-[12px] border border-line bg-surface">
        <EmptyState icon={Shield} title="未选择角色" hint="从左侧选择一个角色查看权限。" />
      </div>
    )
  }

  // 看成员 → 只读展示其角色权限;看角色本身且有权限 → 可编辑
  const viewingMember = member !== null
  const editable = canManage && !viewingMember
  const dirty = editable && !sameSet(draft, role.permissions)
  const granted = viewingMember ? new Set(role.permissions) : draft

  const cycle = (cap: Cap) => {
    if (!editable) return
    setDraft((prev) => cycleCap(cap, prev))
  }

  const save = async () => {
    setBusy(true)
    try {
      await updateRole(role.id, { permissions: [...draft] })
      toast.success('权限已保存')
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-[12px] border border-line bg-surface max-lg:min-h-[460px]">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <h3 className="text-[15px] font-semibold text-ink">
          {viewingMember ? `${member.display_name} 的权限` : '角色权限'}
        </h3>
        <span className="font-data text-[13px] text-ink-mute">{granted.size} 项</span>
        {dirty && (
          <Button size="sm" variant="primary" className="ml-auto" onClick={save} disabled={busy}>
            <Save className="h-3.5 w-3.5" />
            保存
          </Button>
        )}
        {!viewingMember && canManage && (
          <div className={cn('flex items-center gap-1', !dirty && 'ml-auto')}>
            <IconButton label="编辑信息" onClick={onEditMeta}>
              <Pencil className="h-[15px] w-[15px]" />
            </IconButton>
            <IconButton label="删除角色" className="hover:text-crit" onClick={onDelete}>
              <Trash2 className="h-[15px] w-[15px]" />
            </IconButton>
          </div>
        )}
      </header>

      {editable ? (
        <p className="border-b border-line bg-subtle px-4 py-2 text-[12.5px] text-ink-mute">
          点击切换:<span className="text-ink-3">无</span> →{' '}
          <span className="font-medium text-accent-ink">只读</span> →{' '}
          <span className="font-medium text-accent-ink">读写</span>
        </p>
      ) : (
        <p className="border-b border-line bg-subtle px-4 py-2 text-[12.5px] text-ink-mute">
          {viewingMember
            ? `继承自角色「${role.name}」`
            : '无管理权限,仅可查看。'}
        </p>
      )}

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
        {groups.map(({ group, caps }) => (
          <div key={group}>
            <div className="mb-2 text-[12px] font-semibold uppercase tracking-wide text-ink-mute">
              {group}
            </div>
            <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
              {caps.map((cap) => (
                <CapCell
                  key={cap.capability}
                  cap={cap}
                  level={levelOf(cap, granted)}
                  editable={editable}
                  dimmed={viewingMember}
                  onClick={() => cycle(cap)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/** 一个能力域单元:三态(无/只读/读写)指示 + 中文名 + 级别徽标。点击循环切换。 */
function CapCell({
  cap,
  level,
  editable,
  dimmed,
  onClick,
}: {
  cap: Cap
  level: 0 | 1 | 2
  editable: boolean
  dimmed: boolean
  onClick: () => void
}) {
  const on = level > 0
  const isAction = !!cap.actionKey
  const badge = isAction ? '已授权' : level === 2 ? '读写' : level === 1 ? '只读' : ''
  // 指示器:无=空框;只读=描边+眼睛;读写/已授权=实心+对勾。
  const Icon = level === 2 || isAction ? Check : Eye
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!editable}
      title={[cap.readKey, cap.writeKey, cap.actionKey].filter(Boolean).join('  ·  ')}
      className={cn(
        'focus-ring flex items-center gap-2.5 rounded-[9px] border px-2.5 py-2 text-left transition-colors',
        on ? 'border-accent/40 bg-accent/8' : 'border-line-2 bg-surface hover:border-line-3',
        dimmed && !on && 'opacity-45',
        !editable && 'cursor-default',
      )}
    >
      <span
        className={cn(
          'grid h-[18px] w-[18px] shrink-0 place-items-center rounded-[5px] border transition-colors',
          level === 2
            ? 'border-accent bg-accent text-white'
            : level === 1
              ? 'border-accent bg-accent/15 text-accent'
              : 'border-line-3 bg-surface text-transparent',
        )}
      >
        <Icon className="h-3 w-3" strokeWidth={level === 1 ? 2.2 : 3} />
      </span>
      <span className="min-w-0 flex-1 truncate text-[13.5px] text-ink-2">{cap.cap_label}</span>
      {badge && (
        <span
          className={cn(
            'shrink-0 rounded-full px-1.5 py-0.5 text-[11px] font-medium',
            level === 2 || isAction ? 'bg-accent/12 text-accent-ink' : 'bg-accent/8 text-accent',
          )}
        >
          {badge}
        </span>
      )}
    </button>
  )
}

/** 新建 / 编辑角色信息(名称 + 描述);权限在右栏就地编辑 */
function RoleMetaDialog({
  role,
  onClose,
  onSaved,
}: {
  role: Role | null
  onClose: () => void
  onSaved: (newId?: number) => void
}) {
  const isEdit = role !== null
  const [name, setName] = useState(role?.name ?? '')
  const [description, setDescription] = useState(role?.description ?? '')
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    if (!name.trim()) return toast.error('请填写角色名称')
    setBusy(true)
    try {
      if (isEdit) {
        await updateRole(role.id, { name: name.trim(), description: description.trim() })
        toast.success('已保存')
        onSaved()
      } else {
        const created = await createRole({
          name: name.trim(),
          description: description.trim(),
          permissions: [],
        })
        toast.success('角色已创建,请在右侧勾选权限')
        onSaved(created.id)
      }
      onClose()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '保存失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={isEdit ? '编辑角色信息' : '新建角色'}
      description={isEdit ? undefined : '先创建角色,再到右侧勾选权限点。'}
      widthClassName="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button variant="primary" onClick={submit} disabled={busy}>
            {isEdit ? '保存' : '创建'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">角色名称</span>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="如 值班长" />
        </label>
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">描述</span>
          <Input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="该角色的职责"
          />
        </label>
      </div>
    </Dialog>
  )
}
