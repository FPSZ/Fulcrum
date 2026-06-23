import type { ComponentProps } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

// 助手回复的 Markdown 渲染 —— 标题/表格/列表/代码按控制台设计令牌排版,
// 让回复像 GPT/Claude 一样可读,而非一坨原始 `##`/`|...|`。

const components: ComponentProps<typeof ReactMarkdown>['components'] = {
  p: ({ children }) => <p className="text-[16.5px] leading-[1.75] text-ink-2">{children}</p>,
  h1: ({ children }) => (
    <h1 className="mt-1 text-[20px] font-semibold tracking-tight text-ink">{children}</h1>
  ),
  h2: ({ children }) => (
    <h2 className="mt-1 text-[18px] font-semibold tracking-tight text-ink">{children}</h2>
  ),
  h3: ({ children }) => <h3 className="text-[16px] font-semibold text-ink">{children}</h3>,
  strong: ({ children }) => <strong className="font-semibold text-ink">{children}</strong>,
  em: ({ children }) => <em className="italic">{children}</em>,
  ul: ({ children }) => (
    <ul className="list-disc space-y-1.5 pl-5 text-[16.5px] leading-[1.75] text-ink-2 marker:text-ink-mute">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="list-decimal space-y-1.5 pl-5 text-[16.5px] leading-[1.75] text-ink-2 marker:text-ink-mute">
      {children}
    </ol>
  ),
  li: ({ children }) => <li className="pl-0.5">{children}</li>,
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noreferrer" className="text-accent hover:underline">
      {children}
    </a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-line-2 pl-3 text-[15.5px] text-ink-3">
      {children}
    </blockquote>
  ),
  code: ({ className, children }) => {
    const block = /language-/.test(className ?? '')
    if (block) {
      return (
        <code className="font-mono text-[14px] leading-relaxed text-ink-2">{children}</code>
      )
    }
    return (
      <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[14px] text-ink-2">
        {children}
      </code>
    )
  },
  pre: ({ children }) => (
    <pre className="overflow-x-auto rounded-lg border border-line bg-subtle p-3">{children}</pre>
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto rounded-lg border border-line">
      <table className="w-full border-collapse text-[15px]">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-subtle">{children}</thead>,
  th: ({ children }) => (
    <th className="border-b border-line px-4 py-2.5 text-left font-medium text-ink-2">{children}</th>
  ),
  td: ({ children }) => (
    <td className="border-b border-line px-4 py-2.5 align-top text-ink-2">{children}</td>
  ),
  tr: ({ children }) => <tr className="last:[&>td]:border-0">{children}</tr>,
  hr: () => <hr className="border-line" />,
}

export function Markdown({ children }: { children: string }) {
  return (
    <div className="space-y-2.5">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {children}
      </ReactMarkdown>
    </div>
  )
}
