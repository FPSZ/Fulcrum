import { useState } from 'react'
import {
  Bell,
  Boxes,
  Code2,
  DatabaseBackup,
  FileSearch,
  Info,
  Loader2,
  ShieldCheck,
  SlidersHorizontal,
  type LucideIcon,
} from 'lucide-react'
import { Badge, Button, Input, Select, SettingRow, SettingSection, Switch } from '@/components/ui'
import { useConversationDisplay } from '@/lib/conversation-pref'
import { useDevMode } from '@/lib/dev-mode'
import { cn } from '@/lib/utils'
import { BackupSettings } from '../backup/backup-settings'
import { GatewayUpstreamPanel } from './gateway-upstream'
import { useSettingsForm } from './use-console-settings'

/** 设置面板统一保存条:仅有未保存更改且具「修改设置」权限时可点。 */
function SaveBar({
  dirty,
  saving,
  ro,
  onSave,
}: {
  dirty: boolean
  saving: boolean
  ro: boolean
  onSave: () => void
}) {
  return (
    <SettingRow
      label="保存更改"
      hint={ro ? '只读:需「修改设置」权限' : dirty ? '有未保存的更改' : '已是最新'}
    >
      <Button size="sm" variant="primary" onClick={onSave} disabled={ro || saving || !dirty}>
        {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
        保存
      </Button>
    </SettingRow>
  )
}

/** 设置面板读取中的占位行。 */
function LoadingRow() {
  return (
    <SettingRow label="读取配置中…">
      <Loader2 className="h-4 w-4 animate-spin text-ink-3" />
    </SettingRow>
  )
}

interface Cat {
  id: string
  label: string
  icon: LucideIcon
}
// 顺序按用途分组,从基础到进阶:
// 实例标识 → 安全核心(网关+模型) → 治理合规(审计+通知) → 数据维护 → 开发者 → 关于
const CATS: Cat[] = [
  { id: 'general', label: '通用', icon: SlidersHorizontal },
  { id: 'gateway', label: '安全网关', icon: ShieldCheck },
  { id: 'models', label: '模型接入', icon: Boxes },
  { id: 'audit', label: '审计与留存', icon: FileSearch },
  { id: 'notifications', label: '通知', icon: Bell },
  { id: 'data', label: '数据与备份', icon: DatabaseBackup },
  { id: 'developer', label: '开发者', icon: Code2 },
  { id: 'about', label: '关于', icon: Info },
]

export function SettingsPage() {
  const [cat, setCat] = useState('general')

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex min-h-0 flex-1 flex-col min-[821px]:flex-row">
        {/* 移动端:横向滚动分类条(纵向二级导航在窄屏放不下) */}
        <div className="flex shrink-0 gap-1.5 overflow-x-auto border-b border-line px-3 py-2 min-[821px]:hidden [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
          {CATS.map((c) => {
            const Icon = c.icon
            const active = cat === c.id
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => setCat(c.id)}
                className={cn(
                  'focus-ring flex shrink-0 items-center gap-1.5 rounded-full border px-3 py-1.5 text-[14px] font-medium transition-colors',
                  active
                    ? 'border-accent/30 bg-accent/10 text-accent-ink'
                    : 'border-line-2 text-ink-2 hover:bg-surface-2',
                )}
              >
                <Icon className={cn('h-4 w-4 shrink-0', active ? 'text-accent' : 'text-ink-3')} strokeWidth={1.8} />
                {c.label}
              </button>
            )
          })}
        </div>

        {/* 桌面:纵向二级导航 */}
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
        <div className="min-w-0 flex-1 overflow-y-auto px-4 py-5 md:px-8 md:py-6">
          <div className="mx-auto w-full max-w-[880px]">
            {cat === 'general' && <GeneralPanel />}
            {cat === 'gateway' && <GatewayPanel />}
            {cat === 'models' && <ModelsPanel />}
            {cat === 'audit' && <AuditPanel />}
            {cat === 'data' && <BackupSettings />}
            {cat === 'notifications' && <NotificationsPanel />}
            {cat === 'developer' && <DeveloperPanel />}
            {cat === 'about' && <AboutPanel />}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ============================ 各分类面板 ============================ */

function GeneralPanel() {
  const { form, set, dirty, saving, onSave, loading, ro } = useSettingsForm()
  return (
    <SettingSection title="通用">
      {loading || !form ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label="实例名称" hint="显示在控制台标题与导出报告中">
            <Input
              value={form.instance_name}
              onChange={(e) => set('instance_name', e.target.value)}
              disabled={ro}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label="部署环境">
            <Select
              value={form.environment}
              onValueChange={(v) => set('environment', v as typeof form.environment)}
              disabled={ro}
              options={[
                { value: 'prod', label: '生产' },
                { value: 'staging', label: '预发' },
                { value: 'demo', label: '隔离演示' },
              ]}
            />
          </SettingRow>
          <SettingRow label="界面语言" hint="英文为部分支持">
            <Select
              value={form.language}
              onValueChange={(v) => set('language', v as typeof form.language)}
              disabled={ro}
              options={[
                { value: 'zh', label: '简体中文' },
                { value: 'en', label: 'English' },
              ]}
            />
          </SettingRow>
          <SettingRow label="时区">
            <Select
              value={form.timezone}
              onValueChange={(v) => set('timezone', v as typeof form.timezone)}
              disabled={ro}
              options={[
                { value: 'sh', label: 'Asia/Shanghai (UTC+8)' },
                { value: 'utc', label: 'UTC' },
              ]}
            />
          </SettingRow>
          <SaveBar dirty={dirty} saving={saving} ro={ro} onSave={onSave} />
        </>
      )}
    </SettingSection>
  )
}

function GatewayPanel() {
  return (
    <>
      {/* 真实可配:上游接入(对接后端 /admin/gateway-config) */}
      <GatewayUpstreamPanel />
      {/* 网关边界与默认处置(规划项) */}
      <SettingSection title="网关边界">
        <SettingRow label="失败模式 fail-closed" hint="出错即拦截,强制开启">
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
        <SettingRow label="MCP 工具边界" hint="拦截并归因 MCP 工具调用">
          <Switch defaultChecked />
        </SettingRow>
        <SettingRow label="非 MCP 适配器" hint="为非 MCP 工具接入适配层">
          <Switch />
        </SettingRow>
      </SettingSection>
    </>
  )
}

function ModelsPanel() {
  const { form, loading } = useSettingsForm()
  const m = form?.backend_model
  return (
    <SettingSection title="模型接入" desc="经 .env 注入,控制台只读。">
      {loading || !m ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label="出站端点" hint="OpenAI 兼容 /v1(FULCRUM_MODEL_ENDPOINT)">
            <code className="font-data text-[13px] text-ink-2">{m.endpoint}</code>
          </SettingRow>
          <SettingRow label="模型名" hint="FULCRUM_MODEL_NAME">
            <code className="font-data text-[13px] text-ink-2">{m.model_name}</code>
          </SettingRow>
          <SettingRow label="API 密钥" hint="经 .env 注入,不在控制台存储 / 展示">
            <Badge tone={m.key_set ? 'ok' : 'high'}>{m.key_set ? '已配置' : '未配置'}</Badge>
          </SettingRow>
          <SettingRow label="被保护的企业智能体" hint="网关放行后转发的上游,在「安全网关 → 上游接入」配置">
            <Badge tone="neutral">见上游接入</Badge>
          </SettingRow>
        </>
      )}
    </SettingSection>
  )
}

function AuditPanel() {
  const [convShow, setConvShow] = useConversationDisplay()
  const { form, set, dirty, saving, onSave, loading, ro } = useSettingsForm()
  return (
    <SettingSection title="审计与留存">
      <SettingRow label="hash-chain 审计" hint="不可篡改,强制开启">
        <Switch defaultChecked disabled />
      </SettingRow>
      <SettingRow label="事件对话展示" hint="详情页呈现对话,已脱敏(本机偏好)">
        <Switch checked={convShow} onCheckedChange={setConvShow} />
      </SettingRow>
      {loading || !form ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label="链校验频率">
            <Select
              value={form.chain_verify_freq}
              onValueChange={(v) => set('chain_verify_freq', v as typeof form.chain_verify_freq)}
              disabled={ro}
              options={[
                { value: 'event', label: '每事件' },
                { value: '5m', label: '每 5 分钟' },
                { value: '1h', label: '每小时' },
              ]}
            />
          </SettingRow>
          <SettingRow label="审计保留期">
            <Select
              value={form.audit_retention}
              onValueChange={(v) => set('audit_retention', v as typeof form.audit_retention)}
              disabled={ro}
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
              value={form.export_format}
              onValueChange={(v) => set('export_format', v as typeof form.export_format)}
              disabled={ro}
              options={[
                { value: 'jsonl', label: 'JSONL' },
                { value: 'csv', label: 'CSV' },
              ]}
            />
          </SettingRow>
          <SaveBar dirty={dirty} saving={saving} ro={ro} onSave={onSave} />
        </>
      )}
    </SettingSection>
  )
}

function NotificationsPanel() {
  const { form, set, dirty, saving, onSave, loading, ro } = useSettingsForm()
  return (
    <SettingSection title="通知">
      {loading || !form ? (
        <LoadingRow />
      ) : (
        <>
          <SettingRow label="严重事件即时通知">
            <Switch
              checked={form.notify_severe}
              onCheckedChange={(v) => set('notify_severe', v)}
              disabled={ro}
            />
          </SettingRow>
          <SettingRow label="待审批提醒" hint="有工具调用转人工审批时提醒">
            <Switch
              checked={form.notify_approval}
              onCheckedChange={(v) => set('notify_approval', v)}
              disabled={ro}
            />
          </SettingRow>
          <SettingRow label="通知渠道">
            <Select
              value={form.notify_channel}
              onValueChange={(v) => set('notify_channel', v as typeof form.notify_channel)}
              disabled={ro}
              options={[
                { value: 'inapp', label: '站内' },
                { value: 'webhook', label: 'Webhook' },
                { value: 'email', label: '邮件' },
              ]}
            />
          </SettingRow>
          <SaveBar dirty={dirty} saving={saving} ro={ro} onSave={onSave} />
        </>
      )}
    </SettingSection>
  )
}

function DeveloperPanel() {
  const [devMode, setDevMode] = useDevMode()
  return (
    <SettingSection title="开发者" desc="开发与演示用页面,默认隐藏。">
      <SettingRow label="开发者模式" hint="开启后侧栏显示「网关实测」「评测验证」">
        <Switch checked={devMode} onCheckedChange={setDevMode} />
      </SettingRow>
      <SettingRow label="网关实测" hint="手动发请求看网关处置与端到端链路">
        <Badge tone={devMode ? 'accent' : 'neutral'}>{devMode ? '显示' : '隐藏'}</Badge>
      </SettingRow>
      <SettingRow label="评测验证" hint="测试集 ASR/FPR/召回记分卡">
        <Badge tone={devMode ? 'accent' : 'neutral'}>{devMode ? '显示' : '隐藏'}</Badge>
      </SettingRow>
    </SettingSection>
  )
}

function AboutPanel() {
  return (
    <SettingSection title="关于">
      <SettingRow label="产品">
        <span className="text-[15px] text-ink-2">枢衡 Fulcrum · 安全控制台</span>
      </SettingRow>
      <SettingRow label="版本">
        <span className="font-data text-[14px] text-ink-2">0.1.0</span>
      </SettingRow>
      <SettingRow label="部署形态">
        <Badge tone="accent">私有化 · 单租户 · 自托管</Badge>
      </SettingRow>
      <SettingRow label="许可证">
        <span className="text-[15px] text-ink-2">内部评估版</span>
      </SettingRow>
    </SettingSection>
  )
}
