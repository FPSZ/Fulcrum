import type { MessageKey } from '../../index'

// Tool Gateway page.
export const tools: Partial<Record<MessageKey, string>> = {
  'tools.empty.title': 'No tool calls yet',
  'tools.empty.hint': 'Tool calls passing through Fulcrum appear here. You can also load a demo backup under "Data & backup".',
  'tools.execute.tool': 'Tool name',
  'tools.execute.arguments': 'Arguments JSON',
  'tools.execute.propose': 'Create proposal',
  'tools.execute.confirm': 'Confirm execution',
  'tools.execute.invalid_args': 'Arguments must be a JSON object.',
  'tools.execute.failed': 'Tool call request failed.',

  'tools.summary': '{total} recent calls, {held} of them controlled (blocked / reviewed)',

  'tools.filter.all': 'All',
  'tools.filter.held': 'Controlled',
  'tools.filter.allow': 'Allowed',

  'tools.col.time': 'Time',
  'tools.col.tool': 'Tool · arguments',
  'tools.col.source': 'Source',
  'tools.col.risk': 'Risk',
  'tools.col.attribution': 'Attribution',
  'tools.col.disposition': 'Disposition',

  'tools.disp.block': 'Blocked',
  'tools.disp.approve': 'Review',
  'tools.disp.sanitize': 'Sanitize',
  'tools.disp.allow': 'Allow',

  'tools.trust.untrusted': 'Untrusted',
  'tools.trust.semi': 'Semi-trusted',
  'tools.trust.trusted': 'Trusted',
}
