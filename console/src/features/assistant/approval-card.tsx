import { useState } from 'react'
import { motion } from 'motion/react'
import { Check, Loader2, Send, ShieldAlert } from 'lucide-react'
import { EASE, type ApprovalState } from './data'

// ─────────────────────────── 待审批:发起申请卡片(复用提案卡外壳 + 审批理由框)──────────

/** 闸判「待审批」→ 当面卡片(与写提案卡同一套外壳):操作员填审批理由,点「发起」才落真工单。 */
export function ApprovalCard({
  a,
  onFile,
}: {
  a: ApprovalState
  onFile: (reason: string) => void
}) {
  const { request: r, status } = a
  const [reason, setReason] = useState('')
  const editing = status === 'idle' || status === 'failed'

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.985, y: 8 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.26, ease: EASE }}
      className="space-y-3 rounded-2xl border border-line bg-surface p-4 shadow-sm"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent/12 text-accent">
            <ShieldAlert className="h-4 w-4" />
          </span>
          <span className="truncate text-[15px] font-medium text-ink">{r.title}</span>
        </div>
        <span className="shrink-0 rounded-full bg-accent/10 px-2 py-0.5 text-[12px] font-medium text-accent-ink">
          需管理员审批
        </span>
      </div>

      {/* 触发依据:凭什么判待审(脱敏摘要,供操作员核对) */}
      {r.excerpt && (
        <div className="rounded-lg bg-surface-2 px-3 py-2 text-[13px] leading-snug text-ink-2">
          {r.excerpt}
        </div>
      )}

      {/* 审批理由:操作员自己填,随工单一并提交给管理员 */}
      <div>
        <div className="mb-1.5 text-[13px] font-medium text-ink-2">审批理由</div>
        <textarea
          value={reason}
          disabled={!editing}
          onChange={(e) => setReason(e.target.value)}
          rows={2}
          placeholder="说明为什么需要执行这一步,管理员据此审批…"
          className="focus-ring min-h-[60px] w-full resize-y rounded-lg border border-line-2 bg-surface px-3 py-2 text-[14px] leading-6 text-ink outline-none placeholder:text-ink-mute disabled:opacity-60"
        />
      </div>

      <div className="flex items-center gap-2">
        {editing && (
          <>
            <motion.button
              whileTap={{ scale: 0.95 }}
              onClick={() => onFile(reason.trim())}
              disabled={!reason.trim()}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-[14px] font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              {status === 'failed' ? '重试发起' : '发起审批申请'}
            </motion.button>
            <span className="text-[13px] text-ink-mute">不发起则不留工单</span>
          </>
        )}
        {status === 'filing' && (
          <span className="flex items-center gap-1.5 text-[13.5px] text-ink-3">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> 发起中…
          </span>
        )}
        {status === 'filed' && (
          <span className="inline-flex items-center gap-1.5 text-[13.5px] text-accent-ink">
            <Check className="h-3.5 w-3.5" /> 已进入待审批,管理员处理中
          </span>
        )}
      </div>
    </motion.div>
  )
}
