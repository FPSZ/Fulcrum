import { useMemo, useState } from 'react'
import { Check, Lock, Pencil, Plus, Shield, Trash2 } from 'lucide-react'
import { Badge, Button, Dialog, EmptyState, IconButton, Input, toast } from '@/components/ui'
import { cn } from '@/lib/utils'
import {
  createRole,
  deleteRole,
  updateRole,
  type PermissionDef,
  type Role,
} from '@/lib/admin'

interface Props {
  roles: Role[]
  permissions: PermissionDef[]
  canManage: boolean
  onChanged: () => void
}

interface DialogState {
  mode: 'create' | 'edit' | 'view'
  id?: number
  name: string
  description: string
  permissions: Set<string>
  isSystem: boolean
}

export function RolesTab({ roles, permissions, canManage, onChanged }: Props) {
  const [dialog, setDialog] = useState<DialogState | null>(null)
  const [busy, setBusy] = useState(false)

  const groups = useMemo(() => {
    const order = ['监测', '管控', '取证', '系统']
    const map = new Map<string, PermissionDef[]>()
    permissions.forEach((p) => {
      const arr = map.get(p.group) ?? []
      arr.push(p)
      map.set(p.group, arr)
    })
    return order.filter((g) => map.has(g)).map((g) => ({ group: g, items: map.get(g)! }))
  }, [permissions])

  const openCreate = () =>
    setDialog({ mode: 'create', name: '', description: '', permissions: new Set(), isSystem: false })
  const openRole = (r: Role) =>
    setDialog({
      mode: r.is_system ? 'view' : 'edit',
      id: r.id,
      name: r.name,
      description: r.description,
      permissions: new Set(r.permissions),
      isSystem: r.is_system,
    })

  const remove = async (r: Role) => {
    try {
      await deleteRole(r.id)
      toast.success('已删除角色')
      onChanged()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '删除失败')
    }
  }

  const submit = async () => {
    if (!dialog || dialog.mode === 'view') return
    if (!dialog.name.trim()) return toast.error('请填写角色名称')
    setBusy(true)
    try {
      const payload = {
        name: dialog.name.trim(),
        description: dialog.description.trim(),
        permissions: [...dialog.permissions],
      }
      if (dialog.mode === 'create') {
        await createRole(payload)
        toast.success('角色已创建')
      } else {
        await updateRole(dialog.id!, payload)
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

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {canManage && (
        <div className="mb-3 flex">
          <Button variant="primary" className="ml-auto" onClick={openCreate}>
            <Plus className="h-4 w-4" />
            新建角色
          </Button>
        </div>
      )}

      <div className="grid min-h-0 flex-1 content-start gap-2.5 overflow-auto sm:grid-cols-2 xl:grid-cols-3">
        {roles.map((r) => (
          <button
            key={r.id}
            type="button"
            onClick={() => openRole(r)}
            className="focus-ring group flex flex-col rounded-[12px] border border-line bg-surface p-3.5 text-left shadow-card transition-colors hover:border-line-3"
          >
            <div className="flex items-center gap-2">
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-[9px] bg-accent/10 text-accent">
                <Shield className="h-[17px] w-[17px]" strokeWidth={1.9} />
              </span>
              <span className="min-w-0 flex-1 truncate text-[15px] font-semibold text-ink">
                {r.name}
              </span>
              {r.is_system ? (
                <Badge tone="neutral">
                  <Lock className="h-3 w-3" />
                  内置
                </Badge>
              ) : (
                <Badge tone="accent">自定义</Badge>
              )}
            </div>
            <p className="mt-2 line-clamp-2 min-h-[34px] text-[13px] leading-relaxed text-ink-3">
              {r.description || '暂无描述'}
            </p>
            <div className="mt-2 flex items-center gap-3 text-[12.5px] text-ink-mute">
              <span>{r.permissions.length} 项权限</span>
              <span>·</span>
              <span>{r.member_count} 名成员</span>
              {canManage && !r.is_system && (
                <span className="ml-auto flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
                  <IconButton
                    label="编辑"
                    onClick={(e) => {
                      e.stopPropagation()
                      openRole(r)
                    }}
                  >
                    <Pencil className="h-[14px] w-[14px]" />
                  </IconButton>
                  <IconButton
                    label="删除"
                    className="hover:text-crit"
                    onClick={(e) => {
                      e.stopPropagation()
                      void remove(r)
                    }}
                  >
                    <Trash2 className="h-[14px] w-[14px]" />
                  </IconButton>
                </span>
              )}
            </div>
          </button>
        ))}
        {roles.length === 0 && (
          <div className="col-span-full">
            <EmptyState icon={Shield} title="暂无角色" hint="新建一个自定义角色并勾选权限点。" />
          </div>
        )}
      </div>

      {dialog && (
        <Dialog
          open
          onOpenChange={(o) => !o && setDialog(null)}
          title={
            dialog.mode === 'create' ? '新建角色' : dialog.mode === 'edit' ? '编辑角色' : '角色详情'
          }
          description={
            dialog.mode === 'view' ? '内置角色不可修改,如需调整请新建自定义角色。' : '勾选该角色可访问的权限点。'
          }
          widthClassName="max-w-2xl"
          footer={
            dialog.mode === 'view' ? (
              <Button variant="secondary" onClick={() => setDialog(null)}>关闭</Button>
            ) : (
              <>
                <Button variant="ghost" onClick={() => setDialog(null)}>取消</Button>
                <Button variant="primary" onClick={submit} disabled={busy}>
                  {dialog.mode === 'create' ? '创建' : '保存'}
                </Button>
              </>
            )
          }
        >
          <RoleForm dialog={dialog} setDialog={setDialog} groups={groups} />
        </Dialog>
      )}
    </div>
  )
}

function RoleForm({
  dialog,
  setDialog,
  groups,
}: {
  dialog: DialogState
  setDialog: (d: DialogState) => void
  groups: { group: string; items: PermissionDef[] }[]
}) {
  const readOnly = dialog.mode === 'view'
  const toggle = (key: string) => {
    if (readOnly) return
    const next = new Set(dialog.permissions)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    setDialog({ ...dialog, permissions: next })
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">角色名称</span>
          <Input
            value={dialog.name}
            disabled={readOnly}
            onChange={(e) => setDialog({ ...dialog, name: e.target.value })}
            placeholder="如 值班长"
          />
        </label>
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">描述</span>
          <Input
            value={dialog.description}
            disabled={readOnly}
            onChange={(e) => setDialog({ ...dialog, description: e.target.value })}
            placeholder="该角色的职责"
          />
        </label>
      </div>

      <div className="space-y-3">
        {groups.map(({ group, items }) => (
          <div key={group}>
            <div className="mb-1.5 text-[12.5px] font-semibold text-ink-mute">{group}</div>
            <div className="grid grid-cols-2 gap-1.5">
              {items.map((p) => {
                const on = dialog.permissions.has(p.key)
                return (
                  <button
                    key={p.key}
                    type="button"
                    onClick={() => toggle(p.key)}
                    disabled={readOnly}
                    className={cn(
                      'focus-ring flex items-center gap-2 rounded-[9px] border px-2.5 py-2 text-left text-[13.5px] transition-colors',
                      on
                        ? 'border-accent/40 bg-accent/8 text-ink'
                        : 'border-line-2 bg-surface text-ink-2 hover:border-line-3',
                      readOnly && 'cursor-default opacity-90',
                    )}
                  >
                    <span
                      className={cn(
                        'grid h-[16px] w-[16px] shrink-0 place-items-center rounded-[5px] border transition-colors',
                        on ? 'border-accent bg-accent text-white' : 'border-line-3 bg-surface',
                      )}
                    >
                      {on && <Check className="h-3 w-3" strokeWidth={3} />}
                    </span>
                    <span className="min-w-0 flex-1 truncate">{p.label}</span>
                    <code className="font-data text-[11.5px] text-ink-mute">{p.key}</code>
                  </button>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
