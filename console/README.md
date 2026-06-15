# 枢衡 Fulcrum · 安全控制台(console)

私有化部署的 Web 控制台前端。技术栈与视觉语言均已锁定,新功能在此基础上扩展。

> 规范见 [docs/arch/02-前端骨架与扩展规范.md](../docs/arch/02-前端骨架与扩展规范.md);整体进度见 [docs/plan/03-进度看板.md](../docs/plan/03-进度看板.md)。

## 运行

```bash
cd console
npm install        # 已配置 npmmirror 镜像源(.npmrc)
npm run dev        # http://localhost:5173
npm run build      # tsc --noEmit && vite build
npm run typecheck
```

## 技术栈

React 18 + TypeScript + Vite 6 · Tailwind v4(CSS-first `@theme`)· Radix UI ·
自研组件库 · motion(动画)· lucide-react(图标)· sonner(toast)。

> 重型库(TanStack Table / Recharts / React Flow / CodeMirror / React Query /
> React Hook Form + Zod)按功能页面**渐进安装**,不一次性堆入(见选型文档原则)。

## 目录

```
src/
  index.css                设计令牌(@theme)+ 字体 + 关键帧 + 焦点环
  lib/
    utils.ts               cn() 类名合并
    motion.ts              统一过渡曲线与动效变体
    module/                ★ 功能模块插件系统(FeatureModule 契约 + 注册表)
    backup/                ★ 备份导入引擎(资源注册表 + 导入/导出 + Provider)
  components/
    ui/                    ★ 自研组件库(分类归档,统一从 '@/components/ui' 引入)
      inputs/              Button · IconButton · Segmented · Input · Switch · Select
      data-display/        Badge · StatusDot · Avatar · Kbd · KeyValue
      overlay/             Tooltip
      feedback/            Skeleton · EmptyState · Toaster(+toast)
      layout/              Card · Separator · SettingSection/Row
      index.ts             统一出口
    app/                   AppShell · Sidebar · Placeholder
  features/
    register.ts            ★ 唯一装配清单:加页面在此加一行
    placeholders.tsx       未实现页面的占位模块
    events/                实时事件页(master-detail)
      module.tsx · backup.ts · evidence-chain.tsx · events-page.tsx …
    settings/              系统设置(8 类二级导航)+ module.tsx
    backup/                备份导入 UI(导入按钮 / 数据与备份面板)
```

## 加一个页面(插件式,3 步)

```
1. features/<x>/<x>-page.tsx     写页面,复用 @/components/ui
2. features/<x>/module.tsx       defineFeature({ id,label,icon,group,order,component[,resources] })
3. features/register.ts          FEATURES 数组加一行
→ 导航 / 路由 / 备份资源自动接上,不改 App.tsx、不改 Sidebar
```

## 设计令牌

定义在 `src/index.css` 的 `@theme` 中,直接映射为 Tailwind 工具类:

- 表层 `bg-canvas / bg-surface / bg-surface-2 / bg-inset`
- 文字 `text-ink / text-ink-2 / text-ink-3 / text-ink-mute`
- 边框 `border-line / border-line-2`(半透明发丝边)
- 强调 `bg-accent / text-accent-ink`(**宝蓝 `#3b6ef6`**,hover `#2f5fe0`,全 UI 唯一色相)
- 玻璃 `.glass-panel`(磨砂玻璃外壳)/ `.glass-card`(次级玻璃卡),浮在哑光浅灰桌面 + 暖橙/冷蓝双光晕背景上
- 状态 `crit / high / med / ok / info`(仅用于真实状态)
- 阴影 `shadow-xs / shadow-card / shadow-pop`,圆角 `rounded-xs/sm/md/lg`
- 焦点环统一用 `.focus-ring` 工具类(键盘可见)

## 约定

- 颜色只表状态,强调色只有宝蓝(`#3b6ef6`)一种色相;能用图形/颜色就不写字。
- 组件先进 `components/ui` 并归类,再在 `features/*` 组合;不要在页面里散写基础样式。
- 动画走 `lib/motion.ts` 的统一曲线;尊重 `prefers-reduced-motion`。

## 当前进度

- ✅ 工程骨架 + 设计令牌 + 自研组件库
- ✅ 倒 L 外壳 + 可收缩侧栏
- ✅ 功能模块插件系统(`lib/module` + `features/register.ts`)
- ✅ 备份导入系统(`lib/backup`,版本化容器 + 资源注册表)
- ✅ 实时事件页(master-detail + 证据归因链)、系统设置页(8 类)
- 🚧 总览 / 策略中心 / 工具网关 / 供应链 / 审计溯源 / 评测验证(占位)
- ⏳ 接后端 OpenAPI(当前为备份导入的 mock 数据)

> 跨前后端的完整进度以 [docs/plan/03-进度看板.md](../docs/plan/03-进度看板.md) 为准。
