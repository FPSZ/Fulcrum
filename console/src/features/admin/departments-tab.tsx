import { useState } from 'react'
import { Building2, FolderPlus, Pencil, Plus, Trash2 } from 'lucide-react'
import { Button, Dialog, EmptyState, IconButton, Input, Select, toast } from '@/components/ui'
import { cn } from '@/lib/utils'
import {
  createDepartment,
  deleteDepartment,
  updateDepartment,
  type Department,
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
                {canManage && (
                  <div className="flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
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
    </div>
  )
}
