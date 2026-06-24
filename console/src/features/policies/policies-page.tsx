import { useMemo, useState } from 'react'
import { ArrowRight, Pencil, Plus, Scale, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'
import {
  Badge,
  type BadgeTone,
  Button,
  Card,
  EmptyState,
  Input,
  Segmented,
  Select,
  type SelectOption,
  Switch,
} from '@/components/ui'
import { useAuth } from '@/lib/auth'
import { type Disposition, type PolicyRule, type PolicySet } from './data'
import { usePolicies, useUpdatePolicies } from './use-policies'

const DISP_TONE: Record<Disposition, BadgeTone> = {
  block: 'crit',
  approve: 'high',
  sanitize: 'med',
  allow: 'ok',
}
const DISP_LABEL: Record<Disposition, string> = {
  block: '阻断',
  approve: '审批',
  sanitize: '净化',
  allow: '放行',
}
const DISP_OPTIONS: SelectOption[] = (['allow', 'sanitize', 'approve', 'block'] as Disposition[]).map(
  (d) => ({ value: d, label: DISP_LABEL[d] }),
)
const LEVEL_TONE: Record<string, BadgeTone> = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'neutral',
}

type Filter = 'all' | Disposition
const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'block', label: '阻断' },
  { value: 'approve', label: '审批' },
]

/** 编辑草稿:镜像 PolicySet 的可改字段;rules 保留 when/risk_level 仅供展示,提交时按 id 合回后端。 */
type Draft = Pick<PolicySet, 'default' | 'workspace' | 'allow_domains' | 'rules'>

export function PoliciesPage() {
  const { has } = useAuth()
  const canManage = has('policies.manage')
  // 策略是后端装配的配置事实(/policies),后端在跑即非空;不可达/非 yaml 引擎 → 诚实空态(不塞假数据)。
  const ps = usePolicies().data
  const update = useUpdatePolicies()
  const [filter, setFilter] = useState<Filter>('all')
  const [draft, setDraft] = useState<Draft | null>(null) // 非 null 即编辑模式

  const dirty = useMemo(
    () => draft != null && ps != null && !sameDraft(draft, ps),
    [draft, ps],
  )

  if (!ps) {
    return (
      <EmptyState
        icon={Scale}
        title="暂无装配策略"
        hint="策略来自后端当前加载的 data/policies/*.yml。请确认安全网关后端在运行。"
      />
    )
  }

  const startEdit = () =>
    setDraft({
      default: ps.default,
      workspace: ps.workspace,
      allow_domains: [...ps.allow_domains],
      rules: ps.rules.map((r) => ({ ...r })),
    })

  const save = () => {
    if (!draft) return
    update.mutate(
      {
        default: draft.default,
        workspace: draft.workspace,
        allow_domains: draft.allow_domains,
        rules: draft.rules.map((r) => ({
          id: r.id,
          enabled: r.enabled,
          decision: r.decision,
          reason: r.reason,
        })),
      },
      {
        onSuccess: (next) => {
          setDraft(null)
          toast.success(`策略已更新 · v${next.version} 已热生效`)
        },
        onError: (e) => toast.error(e instanceof Error ? e.message : '保存失败'),
      },
    )
  }

  const rules = draft
    ? draft.rules
    : ps.rules.filter((r) => filter === 'all' || r.decision === filter)
  const patch = (next: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...next } : d))
  const patchRule = (id: string, next: Partial<PolicyRule>) =>
    setDraft((d) =>
      d ? { ...d, rules: d.rules.map((r) => (r.id === id ? { ...r, ...next } : r)) } : d,
    )
  const removeRule = (id: string) =>
    setDraft((d) => (d ? { ...d, rules: d.rules.filter((r) => r.id !== id) } : d))

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
      {/* 顶部状态条 + 编辑/保存动作 */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-ink-3">
          {draft ? (
            <span className="inline-flex items-center gap-1.5">
              默认处置
              <Select
                value={draft.default}
                onValueChange={(v) => patch({ default: v as Disposition })}
                options={DISP_OPTIONS}
                className="w-24"
              />
            </span>
          ) : (
            <span>
              默认处置 <Badge tone={DISP_TONE[ps.default]}>{DISP_LABEL[ps.default]}</Badge>
            </span>
          )}
          {draft ? (
            <span className="inline-flex items-center gap-1.5">
              工作区
              <Input
                value={draft.workspace}
                onChange={(e) => patch({ workspace: e.target.value })}
                className="h-7 w-44"
              />
            </span>
          ) : (
            <span>
              工作区 <code className="text-ink-2">{ps.workspace}</code>
            </span>
          )}
          <span>规则集 v{ps.version}</span>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {draft ? (
            <>
              <Button variant="ghost" size="sm" onClick={() => setDraft(null)}>
                取消
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={!dirty || update.isPending}
                onClick={save}
              >
                {update.isPending ? '保存中…' : '保存并热生效'}
              </Button>
            </>
          ) : (
            canManage && (
              <Button variant="secondary" size="sm" onClick={startEdit}>
                <Pencil className="h-3.5 w-3.5" /> 编辑策略
              </Button>
            )
          )}
        </div>
      </div>

      {/* 外联白名单:编辑态可增删,只读态展示 */}
      <DomainEditor
        domains={draft ? draft.allow_domains : ps.allow_domains}
        editing={draft != null}
        onChange={(allow_domains) => patch({ allow_domains })}
      />

      <div className="flex items-center gap-3">
        <span className="text-[13px] text-ink-3">{rules.length} 条规则</span>
        {!draft && (
          <Segmented value={filter} onValueChange={(v) => setFilter(v as Filter)} items={FILTERS} />
        )}
        {draft && (
          <span className="text-[12.5px] text-ink-3">
            停用的规则在判定时跳过(保留留痕,可随时恢复);删除的规则保存后从策略中移除。
          </span>
        )}
      </div>

      {/* 规则列表 */}
      <div className="space-y-2.5">
        {rules.map((r, i) => (
          <Card
            key={r.id}
            className={`p-3.5 ${draft && !r.enabled ? 'opacity-55' : ''}`}
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="flex h-5 w-5 items-center justify-center rounded-xs bg-surface-2 text-[12px] tabular-nums text-ink-3">
                {i + 1}
              </span>
              <code className="text-[13.5px] font-medium text-ink">{r.id}</code>
              <Badge tone={LEVEL_TONE[r.risk_level] ?? 'neutral'}>{r.risk_level}</Badge>
              {draft ? (
                <div className="ml-auto flex items-center gap-2.5">
                  <Select
                    value={r.decision}
                    onValueChange={(v) => patchRule(r.id, { decision: v as Disposition })}
                    options={DISP_OPTIONS}
                    className="w-24"
                  />
                  <label className="inline-flex items-center gap-1.5 text-[12.5px] text-ink-3">
                    {r.enabled ? '启用' : '停用'}
                    <Switch
                      checked={r.enabled}
                      onCheckedChange={(c) => patchRule(r.id, { enabled: c })}
                    />
                  </label>
                  <button
                    type="button"
                    onClick={() => removeRule(r.id)}
                    className="text-ink-3 transition-colors hover:text-crit"
                    title="删除该规则"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ) : (
                <span className="ml-auto inline-flex items-center gap-1.5 text-[13px] text-ink-3">
                  {!r.enabled && <Badge tone="neutral">已停用</Badge>}
                  条件命中 <ArrowRight className="h-3.5 w-3.5" />
                  <Badge tone={DISP_TONE[r.decision]} dot>
                    {DISP_LABEL[r.decision]}
                  </Badge>
                </span>
              )}
            </div>
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
              {r.when.map((c) => (
                <span
                  key={c.key}
                  className="inline-flex items-center gap-1 rounded-xs border border-line-2 bg-surface px-2 py-0.5 text-[12.5px] text-ink-2"
                >
                  <span className="text-ink-3">{c.key}</span>
                  <span className="text-line-3">=</span>
                  <span className="font-medium">{c.value}</span>
                </span>
              ))}
            </div>
            {draft ? (
              <Input
                value={r.reason}
                onChange={(e) => patchRule(r.id, { reason: e.target.value })}
                placeholder="命中理由(展示给审计/操作员)"
                className="mt-2.5 h-7 text-[13px]"
              />
            ) : (
              <p className="mt-2 text-[13px] leading-relaxed text-ink-2">{r.reason}</p>
            )}
          </Card>
        ))}
      </div>
    </div>
  )
}

/** 外联白名单编辑:编辑态显示可删 chip + 回车新增;只读态一行文字。 */
function DomainEditor({
  domains,
  editing,
  onChange,
}: {
  domains: string[]
  editing: boolean
  onChange: (next: string[]) => void
}) {
  const [input, setInput] = useState('')
  if (!editing) {
    return (
      <div className="text-[13px] text-ink-3">外联白名单 {domains.join('、') || '（空）'}</div>
    )
  }
  const add = () => {
    const v = input.trim()
    if (v && !domains.includes(v)) onChange([...domains, v])
    setInput('')
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-[13px] text-ink-3">
      外联白名单
      {domains.map((d) => (
        <span
          key={d}
          className="inline-flex items-center gap-1 rounded-xs border border-line-2 bg-surface px-2 py-0.5 text-[12.5px] text-ink-2"
        >
          {d}
          <button
            type="button"
            onClick={() => onChange(domains.filter((x) => x !== d))}
            className="text-ink-3 hover:text-crit"
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
      <Input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault()
            add()
          }
        }}
        placeholder="添加域名"
        className="h-7 w-32"
      />
      <button type="button" onClick={add} className="text-ink-3 hover:text-accent">
        <Plus className="h-4 w-4" />
      </button>
    </div>
  )
}

/** 草稿与当前策略是否一致(脏检查):比较可编辑字段。 */
function sameDraft(d: Draft, ps: PolicySet): boolean {
  if (d.default !== ps.default || d.workspace !== ps.workspace) return false
  if (d.allow_domains.join(' ') !== ps.allow_domains.join(' ')) return false
  if (d.rules.length !== ps.rules.length) return false
  return d.rules.every((r, i) => {
    const o = ps.rules[i]
    return (
      o != null &&
      r.id === o.id &&
      r.enabled === o.enabled &&
      r.decision === o.decision &&
      r.reason === o.reason
    )
  })
}
