import { useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { Check, ChevronDown, Sparkles, X } from 'lucide-react'
import { Markdown } from './markdown'
import { ProposalCard } from './proposal-card'
import { ApprovalCard } from './approval-card'
import {
  type ApprovalState,
  type AssistantStep,
  type ChatMessage,
  EASE,
  type ProposalState,
} from './data'

// ─────────────────────────── 消息 ───────────────────────────

export function UserTurn({ text }: { text: string }) {
  return (
    <div className="flex justify-end">
      <div className="max-w-[78%] whitespace-pre-wrap rounded-3xl bg-surface-2 px-5 py-3 text-[16.5px] leading-7 text-ink">
        {text}
      </div>
    </div>
  )
}

interface AssistantTurnProps {
  msg: Extract<ChatMessage, { role: 'assistant' }>
  onConfirm: (p: ProposalState) => void
  onCancel: (p: ProposalState) => void
  onUndo: (p: ProposalState) => void
  onEdit: (p: ProposalState, key: string, value: unknown) => void
  onFileApproval: (a: ApprovalState, reason: string) => void
}

export function AssistantTurn({
  msg,
  onConfirm,
  onCancel,
  onUndo,
  onEdit,
  onFileApproval,
}: AssistantTurnProps) {
  return (
    <div className="flex gap-3.5">
      <div className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-full bg-accent/10 text-accent">
        <Sparkles className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1 space-y-3">
        {msg.pending ? (
          <Thinking />
        ) : (
          <>
            {msg.blocked && (
              <div className="inline-flex items-center gap-1.5 rounded-full bg-crit/10 px-2.5 py-1 text-[13px] font-medium text-crit">
                <X className="h-3 w-3" /> 已被安全网关拦截
              </div>
            )}
            {msg.text && (
              <div className="relative">
                <Markdown>{msg.text}</Markdown>
                {msg.streaming && (
                  <span className="ml-0.5 inline-block h-[15px] w-[2px] translate-y-[2px] animate-pulse bg-ink-2 align-middle" />
                )}
              </div>
            )}
            {msg.steps.length > 0 && <Trace steps={msg.steps} />}
            {msg.proposals.map((p) => (
              <ProposalCard
                key={p.id}
                p={p}
                onConfirm={() => onConfirm(p)}
                onCancel={() => onCancel(p)}
                onUndo={() => onUndo(p)}
                onEdit={(k, v) => onEdit(p, k, v)}
              />
            ))}
            {(msg.approvals ?? []).map((a) => (
              <ApprovalCard key={a.id} a={a} onFile={(reason) => onFileApproval(a, reason)} />
            ))}
          </>
        )}
      </div>
    </div>
  )
}

function Thinking() {
  return (
    <div className="flex items-center gap-1.5 py-1">
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-ink-mute [animation-delay:-0.3s]" />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-ink-mute [animation-delay:-0.15s]" />
      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-ink-mute" />
    </div>
  )
}

function Trace({ steps }: { steps: AssistantStep[] }) {
  const [open, setOpen] = useState(false)
  return (
    <div>
      <button
        onClick={() => setOpen((v) => !v)}
        className="focus-ring inline-flex items-center gap-1 rounded-md px-1 text-[13px] text-ink-mute transition-colors hover:text-ink-3"
      >
        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? '' : '-rotate-90'}`} />
        执行过程 · {steps.length} 步
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: EASE }}
            className="overflow-hidden"
          >
            <div className="mt-1.5 space-y-1 border-l border-line pl-3">
              {steps.map((s, i) => (
                <div key={i} className="flex items-start gap-2 text-[13.5px]">
                  {s.ok ? (
                    <Check className="mt-0.5 h-3 w-3 shrink-0 text-ok" />
                  ) : (
                    <X className="mt-0.5 h-3 w-3 shrink-0 text-crit" />
                  )}
                  <span className="shrink-0 text-ink-2">{s.label}</span>
                  <span className="min-w-0 truncate text-ink-mute">{s.detail}</span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
