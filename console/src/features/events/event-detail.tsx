import { AnimatePresence, motion } from 'motion/react'
import { ChevronDown, ChevronUp, Check, FileSearch } from 'lucide-react'
import { Badge, Button, IconButton, KeyValue, StatusDot } from '@/components/ui'
import { detailSwap } from '@/lib/motion'
import { EvidenceChain } from './evidence-chain'
import {
  DISPOSITION_LABEL,
  DISPOSITION_TONE,
  LEVEL_BADGE,
  LEVEL_LABEL,
  TRUST_LABEL,
  TRUST_TONE,
} from './meta'
import type { SecurityEvent } from './types'

export function EventDetail({
  event: e,
  index,
  total,
  onPrev,
  onNext,
}: {
  event: SecurityEvent
  index: number
  total: number
  onPrev?: () => void
  onNext?: () => void
}) {
  return (
    <aside className="flex w-[484px] shrink-0 flex-col border-l border-line bg-surface max-[1320px]:w-[420px] max-[1080px]:hidden">
      {/* 头:会话/事件 + 上下条(高度与左侧工具条 h-11 对齐) */}
      <div className="flex h-11 shrink-0 items-center gap-2.5 border-b border-line px-3.5">
        <span className="text-[12px] text-ink-3">
          会话 <span className="font-data text-ink-2">{e.sess}</span>
          <span className="mx-1.5 text-ink-mute">·</span>
          事件 <span className="font-data text-ink-2">{e.id}</span>
        </span>
        <span className="font-data ml-auto mr-1 text-[12px] text-ink-mute">
          {index + 1}/{total}
        </span>
        <IconButton label="上一条" onClick={onPrev} disabled={!onPrev}>
          <ChevronUp className="h-4 w-4" />
        </IconButton>
        <IconButton label="下一条" onClick={onNext} disabled={!onNext}>
          <ChevronDown className="h-4 w-4" />
        </IconButton>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <AnimatePresence mode="wait">
          <motion.div
            key={e.id}
            variants={detailSwap}
            initial="initial"
            animate="animate"
            exit="exit"
          >
            {/* 标题 + 徽标 */}
            <div className="px-[18px] pb-2 pt-4">
              <h1 className="mb-2.5 text-[18px] font-semibold leading-snug tracking-[-0.02em]">
                {e.risk}
              </h1>
              <Badge tone={LEVEL_BADGE[e.level]} dot>
                {LEVEL_LABEL[e.level]}风险
              </Badge>
              <Badge tone={DISPOSITION_TONE[e.disp]} className="ml-1.5">
                {DISPOSITION_LABEL[e.disp]}
              </Badge>
            </div>

            {/* 属性区 */}
            <div className="border-b border-line px-[18px] pb-3.5 pt-1.5">
              <KeyValue label="来源">
                <StatusDot tone={TRUST_TONE[e.trust]} shape="square" />
                {e.srcType}
                <span className="text-[11px] text-ink-3">{TRUST_LABEL[e.trust]}</span>
              </KeyValue>
              <KeyValue label="工具/动作">
                <span className="font-data">{e.tool}</span>
              </KeyValue>
              <KeyValue label="命中策略">
                <span className="font-data rounded-xs bg-inset px-[7px] py-0.5 text-[11px]">
                  {e.policy}
                </span>
              </KeyValue>
              <KeyValue label="置信度">
                <span className="font-data">{e.conf.toFixed(2)}</span>
              </KeyValue>
              <KeyValue label="时间">
                <span className="font-data">{e.time}</span>
              </KeyValue>
            </div>

            <div className="px-[18px] pb-0.5 pt-3.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-ink-mute">
              证据归因链
            </div>
            <EvidenceChain event={e} />
          </motion.div>
        </AnimatePresence>
      </div>

      {/* 操作 */}
      <div className="flex shrink-0 gap-2.5 border-t border-line px-3.5 py-3">
        {e.disp === 'approve' ? (
          <>
            <Button variant="primary" className="flex-1">
              <Check className="h-3.5 w-3.5" /> 批准放行
            </Button>
            <Button className="flex-1">维持阻断</Button>
          </>
        ) : (
          <>
            <Button className="flex-1">
              <FileSearch className="h-3.5 w-3.5" /> 查看完整链路
            </Button>
            <Button className="flex-1" disabled>
              批量处置
            </Button>
          </>
        )}
      </div>
    </aside>
  )
}
