import { motion } from 'motion/react'
import { PanelLeftClose, PanelLeftOpen, Plus, Trash2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { EASE } from './data'
import type { Conversation } from './use-conversations'

// ─────────────────────────── 会话侧栏(Kimi 式:新建会话 + 历史)───────────────────────────

export function ConversationSidebar({
  history,
  activeId,
  busy,
  collapsed,
  onToggle,
  onNew,
  onSelect,
  onDelete,
}: {
  history: Conversation[]
  activeId: string
  busy: boolean
  collapsed: boolean
  onToggle: () => void
  onNew: () => void
  onSelect: (id: string) => void
  onDelete: (id: string) => void
}) {
  return (
    <motion.aside
      animate={{ width: collapsed ? 56 : 264 }}
      transition={{ duration: 0.22, ease: EASE }}
      className="shrink-0 overflow-hidden border-r border-line bg-surface/50"
    >
      {collapsed ? (
        // 收起态:窄轨,只留「展开」+「新建会话」两个图标
        <div className="flex w-14 flex-col items-center gap-1.5 py-3.5">
          <button
            type="button"
            onClick={onToggle}
            aria-label="展开会话栏"
            className="focus-ring grid h-9 w-9 place-items-center rounded-[11px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink"
          >
            <PanelLeftOpen className="h-[18px] w-[18px]" strokeWidth={1.8} />
          </button>
          <button
            type="button"
            onClick={onNew}
            disabled={busy}
            aria-label="新建会话"
            className="focus-ring grid h-9 w-9 place-items-center rounded-[11px] border border-line-2 bg-surface text-ink transition-colors hover:bg-surface-2 disabled:opacity-50"
          >
            <Plus className="h-[18px] w-[18px]" strokeWidth={2} />
          </button>
        </div>
      ) : (
        <div className="flex h-full w-[264px] flex-col">
          <div className="flex items-center justify-between px-3.5 pb-1 pt-3">
            <span className="text-[13px] font-semibold text-ink-mute">会话</span>
            <button
              type="button"
              onClick={onToggle}
              aria-label="收起会话栏"
              className="focus-ring grid h-7 w-7 place-items-center rounded-md text-ink-mute transition-colors hover:bg-surface-2 hover:text-ink-2"
            >
              <PanelLeftClose className="h-4 w-4" strokeWidth={1.8} />
            </button>
          </div>
          <div className="px-3.5 pb-1 pt-1.5">
            <button
              type="button"
              onClick={onNew}
              disabled={busy}
              className="focus-ring flex w-full items-center gap-2 rounded-xl border border-line-2 bg-surface px-3.5 py-3 text-[14.5px] font-medium text-ink transition-colors hover:border-line-3 hover:bg-surface-2 disabled:opacity-50"
            >
              <Plus className="h-[18px] w-[18px]" strokeWidth={2} /> 新建会话
            </button>
          </div>
          <div className="px-4 pb-2 pt-2.5 text-[12.5px] font-semibold tracking-wide text-ink-mute">
            历史会话
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-2.5 pb-3">
            {history.length === 0 ? (
              <p className="px-2 py-8 text-center text-[13px] leading-relaxed text-ink-mute">
                暂无历史会话
                <br />
                开始对话即在此留存
              </p>
            ) : (
              history.map((c) => {
                const active = c.id === activeId
                return (
                  <div
                    key={c.id}
                    className={cn(
                      'group flex items-center gap-1 rounded-lg px-3 py-2.5 transition-colors',
                      active ? 'bg-accent/12' : 'hover:bg-surface-2',
                    )}
                  >
                    <button
                      type="button"
                      onClick={() => onSelect(c.id)}
                      className="min-w-0 flex-1 text-left"
                    >
                      <span
                        className={cn(
                          'block truncate text-[14px]',
                          active ? 'font-medium text-accent-ink' : 'text-ink-2',
                        )}
                      >
                        {c.title || '新对话'}
                      </span>
                    </button>
                    <button
                      type="button"
                      aria-label="删除会话"
                      onClick={() => onDelete(c.id)}
                      className="focus-ring grid h-6 w-6 shrink-0 place-items-center rounded-md text-ink-mute opacity-0 transition-opacity hover:bg-line/40 hover:text-ink-2 group-hover:opacity-100"
                    >
                      <Trash2 className="h-3.5 w-3.5" strokeWidth={1.8} />
                    </button>
                  </div>
                )
              })
            )}
          </div>
        </div>
      )}
    </motion.aside>
  )
}
