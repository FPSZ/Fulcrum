import { useState } from 'react'
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

/** 登录后的主控制台(外壳 + 当前页面) */
function AppView() {
  const [view, setView] = useState(() => (getFeature('overview') ? 'overview' : getDefaultFeatureId()))
  return (
    <BackupProvider>
      <TooltipProvider delayDuration={250}>
        <AppShell active={view} onNavigate={setView}>
          <View id={view} />
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
  const { authed } = useAuth()
  return (
    <>
      <BackgroundLayer blurred={authed} />
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
