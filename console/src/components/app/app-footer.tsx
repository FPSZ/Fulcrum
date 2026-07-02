import { ArrowUp, CornerDownRight, Github, Mail } from 'lucide-react'
import { useTranslation } from '@/lib/i18n'
import { cn } from '@/lib/utils'

/** 一个仿照获奖站(kurzform)排版的统一页脚:品牌字组 / 导航 / 合规 / 竖排年号。
 *  视觉:半透明磨砂玻璃盖在 body 背景之上;藏在内容卡之下,卡上滑时露出。 */
export function AppFooter({
  onNavigate,
  onBackToTop,
}: {
  onNavigate?: (id: string) => void
  onBackToTop?: () => void
}) {
  const { t } = useTranslation()
  const nav = [
    { id: 'overview', label: t('app.footer.nav.overview') },
    { id: 'events', label: t('app.footer.nav.events') },
    { id: 'admin-users', label: t('app.footer.nav.users') },
    { id: 'settings', label: t('app.footer.nav.settings') },
  ]
  const legal = [
    t('app.footer.legal.privacy'),
    t('app.footer.legal.terms'),
    t('app.footer.legal.compliance'),
    t('app.footer.legal.license'),
  ]
  return (
    <div className="relative flex h-full w-full flex-col justify-end overflow-hidden bg-[rgba(255,255,255,0.46)] backdrop-blur-2xl">
      {/* 顶部发丝高光 + 分隔 */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/70" />

      {/* 右侧竖排大年号 —— 低对比、压在角落 */}
      <div
        aria-hidden
        className="pointer-events-none absolute bottom-7 right-7 flex select-none flex-col items-center text-ink/12"
      >
        <span className="text-[58px] font-bold leading-[0.9] tracking-tight [writing-mode:vertical-rl]">
          2026
        </span>
        <span className="mt-2 text-[24px] font-semibold leading-none">©</span>
      </div>

      {/* 回到顶部 */}
      <button
        type="button"
        onClick={onBackToTop}
        aria-label={t('app.footer.back_to_top')}
        className="focus-ring group absolute right-7 top-7 grid h-12 w-12 place-items-center rounded-full border border-line-2 bg-white/55 text-ink-2 transition-all duration-200 hover:-translate-y-0.5 hover:border-accent/40 hover:text-accent"
      >
        <ArrowUp
          className="h-[22px] w-[22px] transition-transform duration-200 group-hover:-translate-y-0.5"
          strokeWidth={1.8}
        />
      </button>

      {/* 主内容栅格(登录页等无导航场景:仅品牌列,占满) */}
      <div
        className={cn(
          'relative grid grid-cols-1 gap-x-10 gap-y-9 px-10 pb-9 pt-12 lg:px-14',
          onNavigate && 'md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]',
        )}
      >
        {/* 品牌字组 */}
        <div>
          <div className="text-[27px] font-bold leading-none tracking-[-0.02em] text-ink">
            枢衡<span className="ml-2 font-semibold text-ink-3">Fulcrum</span>
            <span className="text-accent">.</span>
          </div>
          <p className="mt-4 text-[13.5px] leading-relaxed text-ink-3">
            {t('app.footer.tagline')}
          </p>
          <div className="mt-6 space-y-1 text-[13px] text-ink-mute">
            <p className="tabnum">{t('app.footer.contact')}</p>
            <p>m. security@fulcrum.makerealm.top</p>
          </div>
        </div>

        {/* 导航 */}
        <div className="md:justify-self-end">
          <div className="mb-4 text-[12px] font-semibold uppercase tracking-[0.14em] text-ink-mute">
            {t('app.footer.nav')}
          </div>
          <div className="grid grid-cols-2 gap-x-10 gap-y-2.5">
            {nav.map((n) => (
              <button
                key={n.id}
                type="button"
                onClick={() => onNavigate?.(n.id)}
                className="focus-ring group flex items-center gap-1.5 text-[15px] text-ink-2 transition-colors hover:text-accent"
              >
                <CornerDownRight
                  className="h-[15px] w-[15px] text-ink-mute transition-colors group-hover:text-accent"
                  strokeWidth={1.8}
                />
                <span className="underline-offset-4 group-hover:underline">{n.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 底部条:合规链接 + 社交 + 版权 */}
      <div className="relative flex flex-col gap-4 border-t border-line/70 px-10 py-6 md:flex-row md:items-center md:justify-between lg:px-14">
        <div className="flex flex-wrap items-center gap-x-7 gap-y-2">
          {legal.map((l) => (
            <button
              key={l}
              type="button"
              className="focus-ring text-[13px] text-ink-3 underline-offset-4 transition-colors hover:text-ink hover:underline"
            >
              {l}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-4">
          <span className="hidden text-[12.5px] text-ink-mute sm:inline">
            {t('app.footer.rights')}
          </span>
          <div className="flex items-center gap-2">
            {[
              { Icon: Github, label: 'GitHub' },
              { Icon: Mail, label: t('app.footer.email') },
            ].map(({ Icon, label }) => (
              <button
                key={label}
                type="button"
                aria-label={label}
                className={cn(
                  'focus-ring grid h-9 w-9 place-items-center rounded-full border border-line-2 bg-white/55 text-ink-2',
                  'transition-all duration-200 hover:-translate-y-0.5 hover:border-accent/40 hover:text-accent',
                )}
              >
                <Icon className="h-[16px] w-[16px]" strokeWidth={1.8} />
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
