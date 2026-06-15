import { useState } from 'react'
import {
  Bell,
  Boxes,
  DatabaseBackup,
  FileSearch,
  Info,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  type LucideIcon,
} from 'lucide-react'
import { Badge, Button, Input, Select, SettingRow, SettingSection, Switch } from '@/components/ui'
import { cn } from '@/lib/utils'
import { BackupSettings } from '../backup/backup-settings'

interface Cat {
  id: string
  label: string
  icon: LucideIcon
}
const CATS: Cat[] = [
  { id: 'general', label: '通用', icon: SlidersHorizontal },
  { id: 'gateway', label: '安全网关', icon: ShieldCheck },
  { id: 'models', label: '模型接入', icon: Boxes },
  { id: 'audit', label: '审计与留存', icon: FileSearch },
  { id: 'data', label: '数据与备份', icon: DatabaseBackup },
  { id: 'notifications', label: '通知', icon: Bell },
  { id: 'members', label: '成员与权限', icon: Users },
  { id: 'about', label: '关于', icon: Info },
]

export function SettingsPage() {
  const [cat, setCat] = useState('general')

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex min-h-0 flex-1">
        {/* 设置二级导航 */}
        <nav className="w-56 shrink-0 overflow-y-auto border-r border-line p-2 max-[820px]:hidden">
          {CATS.map((c) => {
            const Icon = c.icon
            const active = cat === c.id
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => setCat(c.id)}
                className={cn(
                  'focus-ring flex w-full items-center gap-2.5 rounded-sm px-2.5 py-1.5 text-[15px] font-normal text-ink-2 transition-colors hover:bg-surface-2',
                  active && 'bg-accent/10 font-semibold text-accent-ink',
                )}
              >
                <Icon
                  className={cn('h-4 w-4 shrink-0', active ? 'text-accent' : 'text-ink-3')}
                  strokeWidth={1.8}
                />
                {c.label}
              </button>
            )
          })}
        </nav>

        {/* 内容 */}
        <div className="min-w-0 flex-1 overflow-y-auto px-8 py-6">
          <div className="mx-auto w-full max-w-[720px]">
            {cat === 'general' && <GeneralPanel />}
            {cat === 'gateway' && <GatewayPanel />}
            {cat === 'models' && <ModelsPanel />}
            {cat === 'audit' && <AuditPanel />}
            {cat === 'data' && <BackupSettings />}
            {cat === 'notifications' && <NotificationsPanel />}
            {cat === 'members' && <MembersPanel />}
            {cat === 'about' && <AboutPanel />}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ============================ 各分类面板 ============================ */

function GeneralPanel() {
  return (
    <SettingSection title="通用" desc="实例标识与界面偏好。">
      <SettingRow label="实例名称" hint="显示在控制台标题与导出报告中">
        <Input defaultValue="雄安政务智能体安全中台" className="w-[280px]" />
      </SettingRow>
      <SettingRow label="部署环境">
        <Select
          defaultValue="demo"
          options={[
            { value: 'prod', label: '生产' },
            { value: 'staging', label: '预发' },
            { value: 'demo', label: '隔离演示' },
          ]}
        />
      </SettingRow>
      <SettingRow label="界面语言">
        <Select
          defaultValue="zh"
          options={[
            { value: 'zh', label: '简体中文' },
            { value: 'en', label: 'English' },
          ]}
        />
      </SettingRow>
      <SettingRow label="时区">
        <Select
          defaultValue="sh"
          options={[
            { value: 'sh', label: 'Asia/Shanghai (UTC+8)' },
            { value: 'utc', label: 'UTC' },
          ]}
        />
      </SettingRow>
    </SettingSection>
  )
}

function GatewayPanel() {
  return (
    <SettingSection title="安全网关" desc="透明安全网关的边界与默认处置策略。">
      <SettingRow
        label="失败模式 fail-closed"
        hint="安全关键路径出错即拦截(架构红线,强制开启)"
      >
        <Switch defaultChecked disabled />
      </SettingRow>
      <SettingRow label="默认处置" hint="未命中放行策略时的兜底动作">
        <Select
          defaultValue="block"
          options={[
            { value: 'block', label: '阻断' },
            { value: 'approve', label: '转人工审批' },
          ]}
        />
      </SettingRow>
      <SettingRow label="OpenAI 兼容入口" hint="经管线的模型请求入口">
        <Input defaultValue="/v1/chat/completions" readOnly className="w-[240px]" />
      </SettingRow>
      <SettingRow label="MCP 工具边界" hint="拦截并归因 MCP 工具调用">
        <Switch defaultChecked />
      </SettingRow>
      <SettingRow label="非 MCP 适配器" hint="为非 MCP 工具接入适配层">
        <Switch />
      </SettingRow>
    </SettingSection>
  )
}

function ModelsPanel() {
  return (
    <SettingSection title="模型接入" desc="后端模型出站配置。密钥仅经 .env 注入,不入前端、不入库。">
      <SettingRow label="供应商">
        <Select
          defaultValue="openai"
          options={[
            { value: 'openai', label: 'OpenAI 兼容' },
            { value: 'vllm', label: '本地 vLLM' },
            { value: 'ollama', label: 'Ollama' },
          ]}
        />
      </SettingRow>
      <SettingRow label="Base URL">
        <Input defaultValue="https://api.internal.gov.example/v1" className="w-[280px]" />
      </SettingRow>
      <SettingRow label="模型名">
        <Input defaultValue="gov-assistant-32b" className="w-[200px]" />
      </SettingRow>
      <SettingRow label="API 密钥" hint="不在控制台存储 / 展示">
        <Badge tone="neutral">经 .env 注入</Badge>
      </SettingRow>
    </SettingSection>
  )
}

function AuditPanel() {
  return (
    <SettingSection title="审计与留存" desc="hash-chain 审计与数据留存策略。">
      <SettingRow label="hash-chain 审计" hint="事件以哈希链串联,可验证不可篡改(强制开启)">
        <Switch defaultChecked disabled />
      </SettingRow>
      <SettingRow label="链校验频率">
        <Select
          defaultValue="event"
          options={[
            { value: 'event', label: '每事件' },
            { value: '5m', label: '每 5 分钟' },
            { value: '1h', label: '每小时' },
          ]}
        />
      </SettingRow>
      <SettingRow label="审计保留期">
        <Select
          defaultValue="1y"
          options={[
            { value: '90d', label: '90 天' },
            { value: '180d', label: '180 天' },
            { value: '1y', label: '1 年' },
            { value: 'forever', label: '永久' },
          ]}
        />
      </SettingRow>
      <SettingRow label="导出格式">
        <Select
          defaultValue="jsonl"
          options={[
            { value: 'jsonl', label: 'JSONL' },
            { value: 'csv', label: 'CSV' },
          ]}
        />
      </SettingRow>
    </SettingSection>
  )
}

function NotificationsPanel() {
  return (
    <SettingSection title="通知" desc="风险事件与待审批的提醒方式。">
      <SettingRow label="严重事件即时通知">
        <Switch defaultChecked />
      </SettingRow>
      <SettingRow label="待审批提醒" hint="有工具调用转人工审批时提醒">
        <Switch defaultChecked />
      </SettingRow>
      <SettingRow label="通知渠道">
        <Select
          defaultValue="inapp"
          options={[
            { value: 'inapp', label: '站内' },
            { value: 'webhook', label: 'Webhook' },
            { value: 'email', label: '邮件' },
          ]}
        />
      </SettingRow>
    </SettingSection>
  )
}

function MembersPanel() {
  const members = [
    { name: '运营·林珩', email: 'lin@gov.example', role: '安全运营', tone: 'accent' as const },
    { name: '审计·周岚', email: 'zhou@gov.example', role: '审计员', tone: 'info' as const },
    { name: '管理·陈默', email: 'chen@gov.example', role: '管理员', tone: 'high' as const },
  ]
  return (
    <SettingSection title="成员与权限" desc="单租户内的成员与角色(RBAC)。">
      {members.map((m) => (
        <SettingRow key={m.email} label={m.name} hint={m.email}>
          <Badge tone={m.tone}>{m.role}</Badge>
        </SettingRow>
      ))}
      <SettingRow label="邀请成员" hint="按角色授予最小权限">
        <Button size="sm" variant="primary">
          邀请
        </Button>
      </SettingRow>
    </SettingSection>
  )
}

function AboutPanel() {
  return (
    <SettingSection title="关于" desc="部署形态与版本信息。">
      <SettingRow label="产品">
        <span className="text-[15px] text-ink-2">枢衡 Fulcrum · 安全控制台</span>
      </SettingRow>
      <SettingRow label="版本">
        <span className="font-data text-[14px] text-ink-2">0.1.0</span>
      </SettingRow>
      <SettingRow label="部署形态" hint="政企数据不出域">
        <Badge tone="accent">私有化 · 单租户 · 自托管</Badge>
      </SettingRow>
      <SettingRow label="许可证">
        <span className="text-[15px] text-ink-2">内部评估版</span>
      </SettingRow>
    </SettingSection>
  )
}
