import { useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { ArrowLeft, Bot, ChevronDown, ChevronUp, Check, FileSearch, ShieldCheck, User } from 'lucide-react'
import { Badge, Button, IconButton, KeyValue, StatusDot } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useConversationDisplay } from '@/lib/conversation-pref'
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

/**
 * 事件对话(用户↔AI)—— 从同会话的真实事件重建,贴在证据归因链上方。
 *
 * 合规:文本取**后端落库前已脱敏**的 excerpt(数据最小化),由「事件对话展示」开关控制是否呈现
 * (见 `lib/conversation-pref`)。默认显最新 2 条,「查看完整对话」展开全部;工具治理类事件无对话上下文。
 */
function ConversationPanel({ event, sessionEvents }: { event: SecurityEvent; sessionEvents: SecurityEvent[] }) {
  const [show] = useConversationDisplay()
  const [expanded, setExpanded] = useState(false)
  if (!show) return null

  const turns = [...sessionEvents]
    .filter((t) => t.excerpt?.trim() && (t.policy === '前置网关' || t.policy === '出口检测'))
    .sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0))
    .map((t) => ({
      id: t.id,
      role: t.policy === '出口检测' ? ('ai' as const) : ('user' as const),
      text: t.excerpt,
      time: t.time,
      current: t.id === event.id,
    }))

  const header = (
    <div className="flex items-center gap-2 px-[18px] pb-3.5 pt-5">
      <span className="text-[12px] font-semibold uppercase tracking-[0.08em] text-ink-mute">对话</span>
      <span className="inline-flex items-center gap-1 rounded-full bg-ok/12 px-1.5 py-0.5 text-[11px] font-medium text-ok">
        <ShieldCheck className="h-3 w-3" />
        已脱敏
      </span>
    </div>
  )

  if (turns.length === 0) {
    return (
      <div className="pb-5">
        {header}
        <p className="px-[18px] text-[13px] leading-relaxed text-ink-3">
          本事件为工具调用治理,无对话上下文(工具意图与参数见下方证据归因链)。
        </p>
      </div>
    )
  }

  const shown = expanded ? turns : turns.slice(-2)
  return (
    <div className="pb-5">
      {header}
      {/* 聊天样式:AI 左、用户右,气泡留白,不套硬框 */}
      <div className="space-y-5 px-[18px]">
        {shown.map((m) => {
          const isUser = m.role === 'user'
          const Icon = isUser ? User : Bot
          return (
            <div key={m.id} className={cn('flex flex-col gap-1.5', isUser ? 'items-end' : 'items-start')}>
              <div className="flex items-center gap-1.5 text-[11.5px] text-ink-mute">
                <Icon className={cn('h-3.5 w-3.5', isUser ? 'text-ink-3' : 'text-accent')} />
                <span className="font-medium text-ink-3">{isUser ? '用户' : 'AI 智能体'}</span>
                {m.current && <span className="text-accent-ink">· 当前</span>}
                <span className="font-data">· {m.time}</span>
              </div>
              <div
                className={cn(
                  'max-w-[85%] whitespace-pre-wrap break-words px-3.5 py-2.5 text-[13.5px] leading-relaxed text-ink',
                  isUser
                    ? 'rounded-[16px] rounded-tr-[4px] bg-accent/10'
                    : 'rounded-[16px] rounded-tl-[4px] bg-surface-2',
                  m.current && 'ring-1 ring-accent/30',
                )}
              >
                {m.text}
              </div>
            </div>
          )
        })}
      </div>
      {turns.length > 2 && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="focus-ring ml-[18px] mt-4 inline-flex items-center gap-1 text-[13px] font-medium text-accent-ink hover:underline"
        >
          {expanded ? '收起对话' : `查看完整对话(共 ${turns.length} 条)`}
          <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', expanded && 'rotate-180')} />
        </button>
      )}
    </div>
  )
}

export function EventDetail({
  event: e,
  index,
  total,
  conversation,
  onBack,
  onPrev,
  onNext,
}: {
  event: SecurityEvent
  index: number
  total: number
  conversation?: SecurityEvent[]
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

            {/* 对话(用户↔AI)—— 真实重建,贴在证据链上方 */}
            <ConversationPanel event={e} sessionEvents={conversation ?? []} />

            <div className="border-t border-line px-[18px] pb-0.5 pt-3.5 text-[12px] font-semibold uppercase tracking-[0.08em] text-ink-mute">
              证据归因链
            </div>
            <EvidenceChain event={e} />
          </motion.div>
        </AnimatePresence>
      </div>
    </aside>
  )
}
