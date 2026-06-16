import { createContext, useContext } from 'react'

/**
 * 功能间跳转上下文 —— 让任意页面组件能切到另一个功能模块(如总览里"查看更多"跳实时事件)。
 * App 在装配处用 setView 提供;页面用 useNavigateFeature() 取一个 navigate(id) 即可。
 */
const NavContext = createContext<(featureId: string) => void>(() => {})

export const NavProvider = NavContext.Provider

export function useNavigateFeature(): (featureId: string) => void {
  return useContext(NavContext)
}
