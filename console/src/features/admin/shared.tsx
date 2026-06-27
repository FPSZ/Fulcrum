import { Copy } from 'lucide-react'
import { Badge, Button, Dialog, toast, type BadgeTone } from '@/components/ui'
import { type MessageKey, t, useTranslation } from '@/lib/i18n'
import type { Department, Role, UserStatus } from '@/lib/admin'

/** 账号状态 → 色调。文案见 statusLabel()(经 t() 在调用时解析当前语言)。 */
export const STATUS_TONE: Record<UserStatus, BadgeTone> = {
  active: 'ok',
  disabled: 'neutral',
  pending: 'med',
  left: 'neutral',
}
const STATUS_KEY: Record<UserStatus, MessageKey> = {
  active: 'admin.status.active',
  disabled: 'admin.status.disabled',
  pending: 'admin.status.pending',
  left: 'admin.status.left',
}
export function statusLabel(status: UserStatus): string {
  return t(STATUS_KEY[status])
}

export function StatusBadge({ status }: { status: UserStatus }) {
  return <Badge tone={STATUS_TONE[status]}>{statusLabel(status)}</Badge>
}

/** epoch 秒 → 本地日期时间;0/空 → 占位 */
export function fmtTime(epoch: number | null | undefined): string {
  if (!epoch) return '—'
  const d = new Date(epoch * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

export function deptName(departments: Department[], id: number | null): string {
  if (id == null) return t('admin.unassigned_dept')
  return departments.find((d) => d.id === id)?.name ?? t('admin.unknown_dept')
}

export function roleName(roles: Role[], id: number | null): string {
  if (id == null) return t('admin.unassigned_role')
  return roles.find((r) => r.id === id)?.name ?? t('admin.unknown_role')
}

export interface DeptNode extends Department {
  children: DeptNode[]
  depth: number
}

/** 扁平部门列表 → 树(按 sort_order 已排序),带 depth 便于缩进 */
export function buildTree(departments: Department[]): DeptNode[] {
  const byId = new Map<number, DeptNode>()
  departments.forEach((d) => byId.set(d.id, { ...d, children: [], depth: 0 }))
  const roots: DeptNode[] = []
  byId.forEach((node) => {
    if (node.parent_id != null && byId.has(node.parent_id)) {
      const parent = byId.get(node.parent_id)!
      node.depth = parent.depth + 1
      parent.children.push(node)
    } else {
      roots.push(node)
    }
  })
  // 重算 depth(父在子之后插入的情况),并展开为先序
  const assign = (nodes: DeptNode[], depth: number) =>
    nodes.forEach((n) => {
      n.depth = depth
      assign(n.children, depth + 1)
    })
  assign(roots, 0)
  return roots
}

/** 先序展开成扁平数组(渲染缩进列表用) */
export function flattenTree(roots: DeptNode[]): DeptNode[] {
  const out: DeptNode[] = []
  const walk = (nodes: DeptNode[]) =>
    nodes.forEach((n) => {
      out.push(n)
      walk(n.children)
    })
  walk(roots)
  return out
}

/** 一次性临时口令展示弹窗(系统生成时)。仅这一次可见,提示尽快转交并改密。 */
export function TempPasswordDialog({
  open,
  onClose,
  username,
  password,
}: {
  open: boolean
  onClose: () => void
  username: string
  password: string
}) {
  const { t } = useTranslation()
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(password)
      toast.success(t('admin.temp_pw.copied'))
    } catch {
      toast.error(t('admin.temp_pw.copy_failed'))
    }
  }
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={t('admin.temp_pw.title')}
      description={t('admin.temp_pw.desc')}
      widthClassName="max-w-md"
      footer={<Button variant="primary" onClick={onClose}>{t('admin.temp_pw.ack')}</Button>}
    >
      <div className="space-y-3">
        <div className="text-[13px] text-ink-3">
          {t('admin.temp_pw.account')} <span className="font-data text-ink-2">{username}</span>
        </div>
        <div className="flex items-center gap-2 rounded-[10px] border border-line-2 bg-subtle px-3 py-2.5">
          <code className="flex-1 select-all break-all font-data text-[15px] text-ink">
            {password}
          </code>
          <Button size="sm" variant="secondary" onClick={copy}>
            <Copy className="h-3.5 w-3.5" />
            {t('admin.temp_pw.copy_btn')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}
