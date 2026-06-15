import { useState, type ReactNode } from 'react'
import { AnimatePresence, MotionConfig, motion } from 'motion/react'
import { AppShell } from './components/app/app-shell'
import { Placeholder } from './components/app/placeholder'
import { LoginPage } from './components/auth/login-page'
import { Toaster, TooltipProvider } from './components/ui'
import { AuthProvider, useAuth } from './lib/auth'
import { BackupProvider } from './lib/backup'
import { BackgroundLayer, BackgroundProvider } from './lib/background'
import { ease } from './lib/motion'
import { getDefaultFeatureId, getFeature } from './lib/module'

/** 按功能模块注册表渲染当前页面 */
function View({ id }: { id: string }) {
  const feature = getFeature(id)
  if (!feature) return <Placeholder title={id} />
  const Page = feature.component
  return <Page />
}

/**
 * 页面切换过场:新页从右侧滑入淡现、旧页向左滑出淡隐,克制快速(Linear 风)。
 * 页面绝对定位叠放 → 两页同时滑动 = 连贯一气;外层 main 的 overflow-hidden 裁掉越界部分。
 */
function PageTransition({ id, children }: { id: string; children: ReactNode }) {
  return (
    <div className="relative min-h-0 flex-1">
      <AnimatePresence initial={false}>
        <motion.div
          key={id}
          initial={{ opacity: 0, x: 22 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -22 }}
          transition={{ duration: 0.26, ease: ease.out }}
          className="absolute inset-0 flex flex-col"
        >
          {children}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

/** 登录后的主控制台(外壳 + 当前页面) */
function AppView() {
  const [view, setView] = useState(() => (getFeature('overview') ? 'overview' : getDefaultFeatureId()))
  return (
    <BackupProvider>
      <TooltipProvider delayDuration={250}>
        <AppShell active={view} onNavigate={setView}>
          <PageTransition id={view}>
            <View id={view} />
          </PageTransition>
        </AppShell>
        <Toaster />
      </TooltipProvider>
    </BackupProvider>
  )
}

/**
 * 门禁 + 过场:未登录显示登录页;登录成功后
 *   1. 登录页向上丝滑滑走
 *   2. 背景在约 1s 内柔和变模糊
 *   3. 主控制台面板从下方弹上来
 * 三段重叠编排成一条连贯动画。`reducedMotion="user"` 尊重系统“减少动态”。
 */
function Shell() {
  const { ready, authed } = useAuth()
  return (
    <>
      <BackgroundLayer blurred={authed} />
      {/* 会话探测完成前只铺背景,不抢先渲染登录页/主控制台,避免刷新瞬间闪一下登录页 */}
      {!ready ? null : (
      <MotionConfig reducedMotion="user">
        <AnimatePresence initial={false}>
          {authed ? (
            <motion.div
              key="app"
              className="fixed inset-0 z-20"
              initial={{ y: '100%' }}
              animate={{ y: 0, transition: { delay: 0.32, duration: 0.72, ease: ease.out } }}
              exit={{ y: '100%', transition: { duration: 0.5, ease: ease.out } }}
            >
              <AppView />
            </motion.div>
          ) : (
            <motion.div
              key="login"
              className="fixed inset-0 z-10"
              initial={{ y: '-100%' }}
              animate={{ y: 0, transition: { duration: 0.55, ease: ease.out } }}
              exit={{ y: '-100%', transition: { duration: 0.62, ease: ease.out } }}
            >
              <LoginPage />
            </motion.div>
          )}
        </AnimatePresence>
      </MotionConfig>
      )}
    </>
  )
}

export function App() {
  return (
    <AuthProvider>
      <BackgroundProvider>
        <Shell />
      </BackgroundProvider>
    </AuthProvider>
  )
}
