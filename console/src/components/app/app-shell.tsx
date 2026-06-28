import { useState, type ReactNode } from 'react'
import { useTranslation } from '@/lib/i18n'
import { getFeature } from '@/lib/module'
import { Sidebar } from './sidebar'
import { MobileDrawer } from './mobile-drawer'
import { Topbar } from './topbar'
import { FooterReveal } from './footer-reveal'

export function AppShell({
  active,
  onNavigate,
  children,
}: {
  active: string
  onNavigate: (id: string) => void
  children: ReactNode
}) {
  const [navCollapsed, setNavCollapsed] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const { t } = useTranslation()
  const activeFeature = getFeature(active)
  const title = activeFeature
    ? activeFeature.labelKey
      ? t(activeFeature.labelKey)
      : activeFeature.label
    : t('app.shell.console')

  /** 移动端点导航后顺手关抽屉 */
  const navigateMobile = (id: string) => {
    onNavigate(id)
    setDrawerOpen(false)
  }

  return (
    <div className="h-screen overflow-hidden">
      {/* 外层"框"= 横贯顶部的顶栏 + 左侧栏连成一体的磨砂面(比内容透一些) */}
      <div
        className="glass-panel flex h-full flex-col overflow-hidden"
        style={{ background: 'rgba(255, 255, 255, 0.86)' }}
      >
        <Topbar
          title={title}
          collapsed={navCollapsed}
          onToggle={() => setNavCollapsed((v) => !v)}
          onMenu={() => setDrawerOpen(true)}
        />
        <div className="flex min-h-0 flex-1 overflow-hidden">
          {/* 桌面侧栏:移动端隐藏,改用抽屉 */}
          <div className="hidden md:flex">
            <Sidebar collapsed={navCollapsed} active={active} onNavigate={onNavigate} />
          </div>
          {/* 内容面:桌面在交界处做小圆角+发丝边;移动端出血占满,无内缩。
              内容卡可上滑揭示底层页脚(仅桌面 / 系统页) */}
          <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
            <FooterReveal onNavigate={onNavigate} navKey={active}>
              {/* 内容面板:桌面端四边细灰线 + 小内缩,像显示器边框把内容"包"起来;移动端出血占满。 */}
              <div className="flex min-h-0 flex-1 flex-col overflow-hidden border-line bg-white/85 backdrop-blur-sm md:m-1.5 md:rounded-[18px] md:border">
                {children}
              </div>
            </FooterReveal>
          </main>
        </div>
      </div>

      {/* 移动端导航抽屉 */}
      <MobileDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)}>
        <Sidebar collapsed={false} active={active} onNavigate={navigateMobile} />
      </MobileDrawer>
    </div>
  )
}
