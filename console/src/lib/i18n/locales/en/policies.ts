import type { MessageKey } from '../../index'

// Policy Center page.
export const policies: Partial<Record<MessageKey, string>> = {
  'policies.empty.title': 'No policies loaded',
  'policies.empty.hint': 'Policies come from the config currently loaded by the backend. Make sure the security gateway backend is running.',

  'policies.default': 'Default disposition',
  'policies.workspace': 'Workspace',
  'policies.allow_domains': 'Outbound allowlist',
  'policies.version': 'Ruleset v{version}',
  'policies.rule_count': '{count} rules',
  'policies.condition_hit': 'Condition match',

  'policies.filter.all': 'All',
  'policies.filter.block': 'Block',
  'policies.filter.approve': 'Review',

  'policies.disp.block': 'Block',
  'policies.disp.approve': 'Review',
  'policies.disp.sanitize': 'Sanitize',
  'policies.disp.allow': 'Allow',
}
