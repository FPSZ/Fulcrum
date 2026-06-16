import { AnimatePresence, motion } from 'motion/react'
import { ArrowLeft, ChevronDown, ChevronUp, Check, FileSearch } from 'lucide-react'
import { Badge, Button, IconButton, KeyValue, StatusDot } from '@/components/ui'
import { cn } from '@/lib/utils'
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
  onBack,
  onPrev,
  onNext,
}: {
  event: SecurityEvent
  index: number
  total: number
  onBack?: () => void
  onPrev?: () => void
  onNext?: () => void
}) {
  return (
    <aside
      className={cn(
        'flex shrink-0 flex-col border-white/50 bg-white/48 backdrop-blur-xl',
        onBack
          ? 'w-full' // 窄屏:全屏接管
          : 'w-[640px] border-l max-[1440px]:w-[560px] max-[1200px]:w-[480px]',
      )}
    >
      {/* 头:操作按钮 + 页码 + 上下条(同一行,高度与左侧工具条 h-12 对齐) */}
      <div className="flex h-12 shrink-0 items-center gap-2.5 border-b border-line px-3.5">
        {onBack && (
          <IconButton label="返回列表" variant="ghost" className="-ml-1.5 h-9 w-9 shrink-0" onClick={onBack}>
            <ArrowLeft className="h-[18px] w-[18px]" />
          </IconButton>
        )}
        {e.disp === 'approve' ? (
          <>
            <Button variant="primary" size="sm" className="flex-1">
              <Check className="h-3.5 w-3.5" /> 批准放行
            </Button>
            <Button size="sm" className="flex-1">维持阻断</Button>
          </>
        ) : (
          <>
            <Button size="sm" className="flex-1">
              <FileSearch className="h-3.5 w-3.5" /> 查看完整链路
            </Button>
            <Button size="sm" className="flex-1" disabled>
              批量处置
            </Button>
          </>
        )}
        <span className="font-data ml-1.5 mr-0.5 shrink-0 text-[14px] text-ink-mute">
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
            {/* 标题 + 会话/事件(右) + 徽标 */}
            <div className="px-[18px] pb-2 pt-4">
              <div className="flex items-start justify-between gap-3">
                <h1 className="min-w-0 text-[20px] font-semibold leading-snug tracking-[-0.02em]">
                  {e.risk}
                </h1>
                <span className="mt-1 shrink-0 text-right text-[13px] leading-snug text-ink-3">
                  会话 <span className="font-data text-ink-2">{e.sess}</span>
                  <span className="mx-1.5 text-ink-mute">·</span>
                  事件 <span className="font-data text-ink-2">{e.id}</span>
                </span>
              </div>
              <div className="mt-2.5">
                <Badge tone={LEVEL_BADGE[e.level]} dot>
                  {LEVEL_LABEL[e.level]}风险
                </Badge>
                <Badge tone={DISPOSITION_TONE[e.disp]} className="ml-1.5">
                  {DISPOSITION_LABEL[e.disp]}
                </Badge>
              </div>
            </div>

            {/* 属性区 */}
            <div className="border-b border-line px-[18px] pb-3.5 pt-1.5">
              <KeyValue label="来源">
                <StatusDot tone={TRUST_TONE[e.trust]} shape="square" />
                {e.srcType}
                <span className="text-[13px] text-ink-3">{TRUST_LABEL[e.trust]}</span>
              </KeyValue>
              <KeyValue label="工具/动作">
                <span className="font-data">{e.tool}</span>
              </KeyValue>
              <KeyValue label="命中策略">
                <span className="font-data rounded-xs bg-inset px-[7px] py-0.5 text-[13px]">
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

            <div className="px-[18px] pb-0.5 pt-3.5 text-[12px] font-semibold uppercase tracking-[0.08em] text-ink-mute">
              证据归因链
            </div>
            <EvidenceChain event={e} />
          </motion.div>
        </AnimatePresence>
      </div>
    </aside>
  )
}
