import { useCallback, useEffect, useState } from 'react'
import { Check, Inbox, X } from 'lucide-react'
import { Avatar, Button, Dialog, EmptyState, Select, toast } from '@/components/ui'
import { useAuth } from '@/lib/auth'
import {
  approveMember,
  listMembers,
  rejectMember,
  type Department,
  type Member,
  type Role,
} from '@/lib/admin'
import { fmtTime } from './shared'

const NONE = '0'

interface Props {
  departments: Department[]
  roles: Role[]
  /** 团队负责人视图:审批只能把人审进自己负责的团队、且只能赋团队级角色(后端亦强制) */
  scoped?: boolean
  onChanged: () => void
}

export function ApprovalsTab({ departments, roles, scoped = false, onChanged }: Props) {
  const { user } = useAuth()
  const managed = new Set(user?.managedTeams ?? [])
  // 负责人:可选部门限本人可管团队,角色限团队级模板;组织审批人不受限。
  const deptOptions = scoped ? departments.filter((d) => managed.has(d.id)) : departments
  const roleOptions = scoped ? roles.filter((r) => r.scope === 'team') : roles
  const [pending, setPending] = useState<Member[]>([])
  const [loading, setLoading] = useState(true)
  const [approving, setApproving] = useState<Member | null>(null)

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      setPending(await listMembers({ status: 'pending' }))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void reload()
  }, [reload])

  const afterChange = () => {
    void reload()
    onChanged()
  }

  const reject = async (m: Member) => {
    try {
      await rejectMember(m.id)
      toast.success('已驳回申请')
      afterChange()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '操作失败')
    }
  }

  if (!loading && pending.length === 0) {
    return <EmptyState icon={Inbox} title="没有待审批的申请" hint="新的账号申请会出现在这里。" />
  }

  return (
    <div className="min-h-0 flex-1 overflow-auto">
      <ul className="space-y-2">
        {pending.map((m) => (
          <li
            key={m.id}
            className="flex items-center gap-3 rounded-[12px] border border-line bg-surface px-3.5 py-3 shadow-card"
          >
            <Avatar fallback={m.display_name.slice(0, 1)} className="h-9 w-9 rounded-[10px]" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-[14.5px] font-semibold text-ink">{m.display_name}</div>
              <div className="truncate font-data text-[12.5px] text-ink-mute">{m.username}</div>
            </div>
            <div className="hidden font-data text-[13px] text-ink-3 sm:block">
              申请于 {fmtTime(m.created_at)}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" onClick={() => reject(m)}>
                <X className="h-3.5 w-3.5" />
                驳回
              </Button>
              <Button variant="primary" size="sm" onClick={() => setApproving(m)}>
                <Check className="h-3.5 w-3.5" />
                批准
              </Button>
            </div>
          </li>
        ))}
      </ul>

      {approving && (
        <ApproveDialog
          member={approving}
          departments={deptOptions}
          roles={roleOptions}
          onClose={() => setApproving(null)}
          onDone={afterChange}
        />
      )}
    </div>
  )
}

function ApproveDialog({
  member,
  departments,
  roles,
  onClose,
  onDone,
}: {
  member: Member
  departments: Department[]
  roles: Role[]
  onClose: () => void
  onDone: () => void
}) {
  const [roleId, setRoleId] = useState<string>(NONE)
  const [deptId, setDeptId] = useState<string>(NONE)
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    setBusy(true)
    try {
      await approveMember(member.id, {
        role_id: roleId === NONE ? null : Number(roleId),
        department_id: deptId === NONE ? null : Number(deptId),
      })
      toast.success(`已批准 ${member.display_name}`)
      onClose()
      onDone()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : '操作失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`批准 ${member.display_name}`}
      description="为该成员指定系统角色与所属部门,批准后即可登录。"
      widthClassName="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button variant="primary" onClick={submit} disabled={busy}>确认批准</Button>
        </>
      }
    >
      <div className="space-y-3">
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">系统角色</span>
          <Select
            value={roleId}
            onValueChange={setRoleId}
            options={[
              { value: NONE, label: '暂不分配' },
              ...roles.map((r) => ({ value: String(r.id), label: r.name })),
            ]}
            className="w-full"
          />
        </label>
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">所属部门</span>
          <Select
            value={deptId}
            onValueChange={setDeptId}
            options={[
              { value: NONE, label: '暂不分配' },
              ...departments.map((d) => ({ value: String(d.id), label: d.name })),
            ]}
            className="w-full"
          />
        </label>
      </div>
    </Dialog>
  )
}
