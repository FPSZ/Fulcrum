import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import { motion } from 'motion/react'
import { ArrowUp, Loader2, Settings2, Square } from 'lucide-react'
import { useTranslation } from '@/lib/i18n'
import { cn } from '@/lib/utils'

// ─────────────────────────── 输入框(GPT/Claude 风格)───────────────────────────

export function Composer({
  onSend,
  onStop,
  busy,
  autoFocus,
  modelReady,
  canConfigure,
  onOpenSettings,
}: {
  onSend: (s: string) => void
  /** 流式生成中的中止回调(M25):传入后 busy 期间发送键变为可点的「停止」。 */
  onStop?: () => void
  busy: boolean
  autoFocus?: boolean
  modelReady: boolean
  canConfigure: boolean
  onOpenSettings: () => void
}) {
  const { t } = useTranslation()
  const [value, setValue] = useState('')
  const ref = useRef<HTMLTextAreaElement>(null)

  const grow = useCallback(() => {
    const el = ref.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`
  }, [])

  useLayoutEffect(grow, [value, grow])

  const submit = () => {
    const t = value.trim()
    if (!t || busy) return
    onSend(t)
    setValue('')
  }

  return (
    // Kimi 比例:圆角 ~18px、内容区高、底部一条工具栏(发送贴右),整体约 140px 高。
    <div className="rounded-[18px] border border-line-2 bg-surface px-4 pb-3 pt-3.5 shadow-sm transition-all focus-within:border-line-3 focus-within:shadow-md">
      <textarea
        ref={ref}
        value={value}
        autoFocus={autoFocus}
        rows={1}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            submit()
          }
        }}
        placeholder={t('assistant.composer.placeholder')}
        className="block min-h-[60px] max-h-[200px] w-full resize-none bg-transparent px-1 text-[16px] leading-7 text-ink outline-none placeholder:text-ink-mute"
      />
      <div className="mt-1 flex items-center justify-between px-0.5">
        <div className="flex items-center gap-2.5">
          <SettingsButton ready={modelReady} canConfigure={canConfigure} onClick={onOpenSettings} />
          <span className="text-[13px] text-ink-mute">
            {modelReady
              ? t('assistant.composer.hint.ready')
              : canConfigure
                ? t('assistant.composer.hint.unconfigured')
                : t('assistant.composer.hint.contact_admin')}
          </span>
        </div>
        {busy && onStop ? (
          // 流式生成中:发送键变「停止」(M25)——网络挂起也能一键解除,不再锁死输入。
          <motion.button
            onClick={onStop}
            aria-label={t('assistant.composer.stop')}
            title={t('assistant.composer.stop')}
            whileTap={{ scale: 0.88 }}
            transition={{ duration: 0.12 }}
            className="focus-ring grid h-9 w-9 place-items-center rounded-full bg-ink text-white transition-colors hover:bg-ink-2"
          >
            <Square className="h-[13px] w-[13px]" fill="currentColor" />
          </motion.button>
        ) : (
          <motion.button
            onClick={submit}
            disabled={busy || !value.trim()}
            aria-label={t('assistant.composer.send')}
            whileTap={{ scale: 0.88 }}
            transition={{ duration: 0.12 }}
            className="focus-ring grid h-9 w-9 place-items-center rounded-full bg-ink text-white transition-colors hover:bg-ink-2 disabled:bg-line-3 disabled:text-white"
          >
            {busy ? (
              <Loader2 className="h-[18px] w-[18px] animate-spin" />
            ) : (
              <ArrowUp className="h-[18px] w-[18px]" />
            )}
          </motion.button>
        )}
      </div>
    </div>
  )
}

/** 设置齿轮:有「AI 模型配置」权限才可点;未配置时蓝色呼吸灯闪烁。无权限 → 灰、禁用、不可点。 */
function SettingsButton({
  ready,
  canConfigure,
  onClick,
}: {
  ready: boolean
  canConfigure: boolean
  onClick: () => void
}) {
  const { t } = useTranslation()
  // 无权限:灰色禁用,不闪呼吸灯,点不动(提示找管理员)。
  if (!canConfigure) {
    return (
      <button
        type="button"
        disabled
        aria-label={t('assistant.composer.settings.no_perm')}
        title={t('assistant.composer.settings.no_perm_title')}
        className="grid h-8 w-8 cursor-not-allowed place-items-center rounded-full text-ink-mute/40"
      >
        <Settings2 className="h-[18px] w-[18px]" strokeWidth={1.9} />
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={t('assistant.composer.settings')}
      title={ready ? t('assistant.composer.settings') : t('assistant.composer.settings.configure')}
      className={cn(
        'focus-ring relative grid h-8 w-8 place-items-center rounded-full transition-colors',
        ready ? 'text-ink-mute hover:bg-surface-2 hover:text-ink-2' : 'text-accent hover:bg-accent/10',
      )}
    >
      {!ready && (
        <>
          <span className="pointer-events-none absolute inset-0 animate-ping rounded-full bg-accent/30" />
          <span className="pointer-events-none absolute inset-0 animate-pulse rounded-full ring-2 ring-accent/50" />
        </>
      )}
      <Settings2 className="relative h-[18px] w-[18px]" strokeWidth={1.9} />
    </button>
  )
}
