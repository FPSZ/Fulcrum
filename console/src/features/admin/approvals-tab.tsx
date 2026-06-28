import { useCallback, useEffect, useState } from 'react'
import { Check, Inbox, X } from 'lucide-react'
import { Avatar, Button, Dialog, EmptyState, Select, toast } from '@/components/ui'
import { useTranslation } from '@/lib/i18n'
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
  const { t } = useTranslation()
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
      toast.error(e instanceof Error ? e.message : t('admin.approvals.load_failed'))
    } finally {
      setLoading(false)
    }
  }, [t])

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
      toast.success(t('admin.approvals.rejected'))
      afterChange()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.approvals.op_failed'))
    }
  }

  if (!loading && pending.length === 0) {
    return (
      <EmptyState
        icon={Inbox}
        title={t('admin.approvals.empty.title')}
        hint={t('admin.approvals.empty.hint')}
      />
    )
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
              {t('admin.approvals.applied_at', { time: fmtTime(m.created_at) })}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" onClick={() => reject(m)}>
                <X className="h-3.5 w-3.5" />
                {t('admin.approvals.reject')}
              </Button>
              <Button variant="primary" size="sm" onClick={() => setApproving(m)}>
                <Check className="h-3.5 w-3.5" />
                {t('admin.approvals.approve')}
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
  const { t } = useTranslation()
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
      toast.success(t('admin.approve.done', { name: member.display_name }))
      onClose()
      onDone()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('admin.approvals.op_failed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={t('admin.approve.title', { name: member.display_name })}
      description={t('admin.approve.desc')}
      widthClassName="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={submit} disabled={busy}>{t('admin.approve.confirm')}</Button>
        </>
      }
    >
      <div className="space-y-3">
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">{t('admin.approve.role')}</span>
          <Select
            value={roleId}
            onValueChange={setRoleId}
            options={[
              { value: NONE, label: t('admin.approve.unassigned') },
              ...roles.map((r) => ({ value: String(r.id), label: r.name })),
            ]}
            className="w-full"
          />
        </label>
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-ink-2">{t('admin.approve.dept')}</span>
          <Select
            value={deptId}
            onValueChange={setDeptId}
            options={[
              { value: NONE, label: t('admin.approve.unassigned') },
              ...departments.map((d) => ({ value: String(d.id), label: d.name })),
            ]}
            className="w-full"
          />
        </label>
      </div>
    </Dialog>
  )
}
