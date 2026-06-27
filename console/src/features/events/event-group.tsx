import { AnimatePresence, motion } from 'motion/react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ease } from '@/lib/motion'
import { DispositionIcon } from './disposition-icon'
import { EventRow } from './event-row'
import { dispositionLabel } from './meta'
import type { Disposition, FoldedRow } from './types'

export function EventGroup({
  disp,
  rows,
  collapsed,
  selectedId,
  onToggle,
  onSelect,
}: {
  disp: Disposition
  rows: FoldedRow[]
  collapsed: boolean
  selectedId: string
  onToggle: () => void
  onSelect: (id: string) => void
}) {
  return (
    <section className="glass-card group/grp overflow-hidden rounded-[12px]">
      <button
        type="button"
        onClick={onToggle}
        className="focus-ring flex w-full items-center gap-2.5 bg-surface-2/55 px-3.5 py-2 text-left text-[13.5px] font-semibold"
      >
        <ChevronDown
          className={cn(
            'h-[15px] w-[15px] text-ink-mute transition-transform duration-150',
            collapsed && '-rotate-90',
          )}
        />
        <DispositionIcon disp={disp} />
        {dispositionLabel(disp)}
        <span className="font-data text-[12.5px] font-medium text-ink-mute">{rows.length}</span>
        <span className="ml-auto text-[12.5px] font-medium text-ink-mute opacity-0 transition-opacity hover:text-ink-3 group-hover/grp:opacity-100">
          批量处置
        </span>
      </button>

      <AnimatePresence initial={false}>
        {!collapsed && (
          <motion.div
            key="rows"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: ease.out }}
            className="overflow-hidden border-t border-line"
          >
            {rows.map((r, i) => (
              <EventRow
                key={r.rep.id}
                event={r.rep}
                count={r.count}
                level={r.level}
                selected={r.rep.id === selectedId}
                last={i === rows.length - 1}
                onSelect={() => onSelect(r.rep.id)}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  )
}
