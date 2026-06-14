# 枢衡 Fulcrum · 安全控制台(console)

私有化部署的 Web 控制台前端。技术栈与视觉语言均已锁定,新功能在此基础上扩展。

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
  components/
    ui/                    ★ 自研组件库(分类归档,统一从 '@/components/ui' 引入)
      inputs/              Button · IconButton · Segmented
      data-display/        Badge · StatusDot · Avatar · Kbd · KeyValue
      overlay/             Tooltip
      feedback/            Skeleton · EmptyState · Toaster(+toast)
      layout/              Card · Separator
      index.ts             统一出口
    app/
      app-shell.tsx        倒 L 外壳(侧栏 + 内容)
      sidebar.tsx          可收缩动画侧栏
  features/
    events/                实时事件页(master-detail)
      types.ts             领域类型
      data.ts              演示数据(无真实 payload/密钥)
      meta.ts              等级/处置/来源/可信度 的标签·配色·图标映射
      disposition-icon.tsx 处置状态图标
      evidence-chain.tsx   证据归因链(签名元素)
      event-row.tsx        事件行(竖色条=等级 / 时间 / 标题 / 来源图标)
      event-group.tsx      按处置分组(可折叠,高度动画)
      event-detail.tsx     右侧常驻详情(属性 + 证据链 + 审批)
      events-page.tsx      页面编排(筛选/选中/键盘/toast)
```

## 设计令牌

定义在 `src/index.css` 的 `@theme` 中,直接映射为 Tailwind 工具类:

- 表层 `bg-canvas / bg-surface / bg-surface-2 / bg-inset`
- 文字 `text-ink / text-ink-2 / text-ink-3 / text-ink-mute`
- 边框 `border-line / border-line-2`(半透明发丝边)
- 强调 `bg-accent / text-accent-ink`(薰衣草蓝,全 UI 唯一色相)
- 状态 `crit / high / med / ok / info`(仅用于真实状态)
- 阴影 `shadow-xs / shadow-card / shadow-pop`,圆角 `rounded-xs/sm/md/lg`
- 焦点环统一用 `.focus-ring` 工具类(键盘可见)

## 约定

- 颜色只表状态,强调色只有薰衣草蓝一种色相;能用图形/颜色就不写字。
- 组件先进 `components/ui` 并归类,再在 `features/*` 组合;不要在页面里散写基础样式。
- 动画走 `lib/motion.ts` 的统一曲线;尊重 `prefers-reduced-motion`。
