import type { MessageKey } from '../../index'

// Live Events.
export const events: Partial<Record<MessageKey, string>> = {
  'events.disp.block': 'Blocked',
  'events.disp.approve': 'Pending review',
  'events.disp.sanitize': 'Sanitized',
  'events.disp.allow': 'Allowed',
  'events.level.critical': 'Critical',
  'events.level.high': 'High',
  'events.level.medium': 'Medium',
  'events.level.low': 'Low',
  'events.level_risk': '{level} risk',
  'events.filter.all': 'All',

  // Empty state
  'events.empty.title': 'No data yet',
  'events.empty.hint': 'Import a backup to view events.',
  'events.none.title': 'No event selected',
  'events.none.hint': 'Pick an item from the list to see its evidence attribution chain',

  // Toolbar
  'events.toolbar.filter': 'Filter',
  'events.toolbar.group': 'Group: disposition',
  'events.toolbar.range': 'Last 24 hours',
  'events.toolbar.export': 'Export report',

  // Disposition toast
  'events.toast.allowed': 'Approved and allowed',
  'events.toast.blocked': 'Kept blocked',
  'events.toast.resolved_desc': 'The disposition is recorded in the audit chain; this pending item is closed.',
  'events.toast.resolve_failed': 'Disposition failed',
  'events.toast.tamper_title': 'Audit chain verification failed',
  'events.toast.tamper_desc': 'Event hashes for session {sess} do not match the chain — suspected tampering; locked and reported.',

  // Detail header
  'events.detail.back': 'Back to list',
  'events.detail.need_handle': 'Requires the "Handle session events" permission',
  'events.detail.approve': 'Approve & allow',
  'events.detail.block': 'Keep blocked',
  'events.detail.full_chain': 'View full chain',
  'events.detail.batch': 'Batch disposition',
  'events.detail.prev': 'Previous',
  'events.detail.next': 'Next',
  'events.detail.session': 'Session',
  'events.detail.event': 'Event',

  // Detail fields
  'events.field.source': 'Source',
  'events.field.tool': 'Tool / action',
  'events.field.policy': 'Matched policy',
  'events.field.conf': 'Confidence',
  'events.field.time': 'Time',

  // Conversation
  'events.conv.title': 'Conversation',
  'events.conv.masked': 'Masked',
  'events.conv.empty': 'This event is tool-call governance, with no conversation context.',
  'events.conv.user': 'User',
  'events.conv.ai': 'AI agent',
  'events.conv.current': 'Current',
  'events.conv.collapse': 'Collapse conversation',
  'events.conv.expand': 'View full conversation ({count} messages)',

  // Evidence attribution chain
  'events.chain.title': 'Evidence attribution chain',
  'events.chain.source': 'Source snippet',
  'events.chain.intent': 'Model intent',
  'events.chain.args': 'Tool arguments',
  'events.chain.derived': 'Evidence-based attribution',
  'events.chain.policy': 'Matched policy',
  'events.chain.disposition': 'Disposition',
  'events.chain.hashchain': 'Audit hash-chain',
  'events.chain.none': 'None',
  'events.chain.conf': 'Confidence {conf}',
  'events.chain.verified': 'Chain verified · 5 consecutive events',
  'events.chain.tamper_title': 'Audit chain verification failed',
  'events.chain.tamper_desc': 'Event #4 hash does not match prev — suspected tampering. Session locked and reported for forensics.',
}
