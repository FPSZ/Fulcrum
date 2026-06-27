import { motion } from 'motion/react'
import { Check, Loader2, RotateCcw } from 'lucide-react'
import { EASE, type ProposalState } from './data'

// ─────────────────────────── 写操作:可编辑提案卡片(VSCode 式差异)───────────────────────────

const RISK_DOT: Record<string, string> = {
  high: 'bg-accent',
  normal: 'bg-med',
  read_only: 'bg-ok',
}

interface ProposalCardProps {
  p: ProposalState
  onConfirm: () => void
  onCancel: () => void
  onUndo: () => void
  onEdit: (key: string, value: unknown) => void
}

export function ProposalCard({ p, onConfirm, onCancel, onUndo, onEdit }: ProposalCardProps) {
  const editing = p.status === 'editing'
  const entries = Object.entries(p.editedArgs)
  const before = p.action.before ?? {}
  const done = p.status === 'done' || p.status === 'undoing' || p.status === 'undone'

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.985, y: 8 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.26, ease: EASE }}
      className="space-y-3 rounded-2xl border border-line bg-surface p-4 shadow-sm"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className={`h-2 w-2 shrink-0 rounded-full ${RISK_DOT[p.action.risk] ?? 'bg-med'}`} />
          <span className="truncate text-[15px] font-medium text-ink">{p.action.label}</span>
        </div>
        <code className="shrink-0 text-[12px] text-ink-mute">{p.action.tool}</code>
      </div>

      {p.action.note && editing && (
        <p className="text-[13.5px] leading-snug text-ink-3">{p.action.note}</p>
      )}

      {entries.length > 0 && (
        <div className="space-y-2">
          {entries.map(([k, v]) => (
            <FieldRow
              key={k}
              name={k}
              value={v}
              hasBefore={k in before}
              before={before[k]}
              disabled={!editing}
              onChange={(nv) => onEdit(k, nv)}
            />
          ))}
        </div>
      )}

      {done && p.resultSummary && (
        <div className="rounded-lg bg-surface-2 px-3 py-2 text-[13.5px] leading-snug text-ink-2">
          {p.resultSummary}
        </div>
      )}

      <div className="flex items-center gap-2">
        {editing && (
          <>
            <motion.button
              whileTap={{ scale: 0.95 }}
              onClick={onConfirm}
              className="focus-ring rounded-lg bg-accent px-3.5 py-2 text-[14px] font-medium text-white transition-colors hover:bg-accent-hover"
            >
              确认执行
            </motion.button>
            <button
              onClick={onCancel}
              className="focus-ring rounded-lg px-3.5 py-2 text-[14px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink-2"
            >
              取消
            </button>
          </>
        )}
        {p.status === 'confirming' && (
          <span className="flex items-center gap-1.5 text-[13.5px] text-ink-3">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> 执行中…
          </span>
        )}
        {p.status === 'cancelled' && <span className="text-[13.5px] text-ink-mute">已取消</span>}
        {p.status === 'done' && p.reversible && p.actionId && (
          <motion.button
            whileTap={{ scale: 0.95 }}
            onClick={onUndo}
            className="focus-ring inline-flex items-center gap-1 rounded-lg border border-line-2 px-3.5 py-2 text-[14px] text-ink-2 transition-colors hover:border-line-3 hover:bg-surface-2"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            撤销{p.undoPreview ? `(${p.undoPreview})` : ''}
          </motion.button>
        )}
        {p.status === 'done' && !(p.reversible && p.actionId) && (
          <span className="inline-flex items-center gap-1 text-[13.5px] text-ok">
            <Check className="h-3.5 w-3.5" /> 已执行
          </span>
        )}
        {p.status === 'undoing' && (
          <span className="flex items-center gap-1.5 text-[13.5px] text-ink-3">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> 撤销中…
          </span>
        )}
        {p.status === 'undone' && (
          <span className="inline-flex items-center gap-1 text-[13.5px] text-ink-mute">
            <RotateCcw className="h-3.5 w-3.5" /> 已撤销
          </span>
        )}
      </div>
    </motion.div>
  )
}

function asText(v: unknown): string {
  if (typeof v === 'boolean') return v ? '是' : '否'
  return String(v ?? '')
}

function FieldRow({
  name,
  value,
  before,
  hasBefore,
  disabled,
  onChange,
}: {
  name: string
  value: unknown
  before: unknown
  hasBefore: boolean
  disabled: boolean
  onChange: (v: unknown) => void
}) {
  const changed = hasBefore && asText(before) !== asText(value)

  // 改动字段:VSCode 式 before→after(红删/绿增),新值可编辑。
  if (changed) {
    return (
      <div className="overflow-hidden rounded-lg border border-line font-mono text-[13.5px]">
        <div className="flex gap-2 bg-crit/8 px-3 py-1.5 text-crit">
          <span className="select-none opacity-60">−</span>
          <span className="shrink-0 opacity-80">{name}:</span>
          <span className="min-w-0 break-all line-through opacity-90">{asText(before)}</span>
        </div>
        <div className="flex items-center gap-2 bg-ok/12 px-3 py-1.5">
          <span className="select-none text-ok opacity-70">+</span>
          <span className="shrink-0 text-ink-3">{name}:</span>
          {typeof value === 'boolean' ? (
            <input
              type="checkbox"
              checked={value}
              disabled={disabled}
              onChange={(e) => onChange(e.target.checked)}
              className="h-[16px] w-[16px] accent-accent disabled:opacity-60"
            />
          ) : (
            <input
              type={typeof value === 'number' ? 'number' : 'text'}
              value={typeof value === 'number' ? value : String(value ?? '')}
              disabled={disabled}
              onChange={(e) =>
                onChange(typeof value === 'number' ? e.target.valueAsNumber : e.target.value)
              }
              className="focus-ring min-w-0 flex-1 rounded border border-ok/30 bg-surface px-2 py-0.5 text-ink disabled:opacity-60"
            />
          )}
        </div>
      </div>
    )
  }

  // 普通字段:紧凑可编辑行。
  return (
    <div className="flex items-center gap-3">
      <label className="w-32 shrink-0 truncate text-[14px] text-ink-3">{name}</label>
      {typeof value === 'boolean' ? (
        <input
          type="checkbox"
          checked={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
          className="h-[18px] w-[18px] accent-accent disabled:opacity-60"
        />
      ) : typeof value === 'number' ? (
        <input
          type="number"
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.valueAsNumber)}
          className="focus-ring h-9 w-full rounded-lg border border-line-2 bg-surface px-3 text-[14px] text-ink disabled:opacity-60"
        />
      ) : (
        <input
          type="text"
          value={String(value ?? '')}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          className="focus-ring h-9 w-full rounded-lg border border-line-2 bg-surface px-3 text-[14px] text-ink disabled:opacity-60"
        />
      )}
    </div>
  )
}
