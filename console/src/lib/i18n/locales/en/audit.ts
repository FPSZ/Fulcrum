import type { MessageKey } from '../../index'

// Audit Trail page.
export const audit: Partial<Record<MessageKey, string>> = {
  'audit.empty.title': 'No audit sessions yet',
  'audit.empty.hint': 'An audit chain is generated after the security gateway handles a request. You can also load a demo backup under "Data & backup".',

  'audit.chain_intact': 'Chain intact',
  'audit.tampered': 'Tampered',
  'audit.verify_pass': 'Hash-chain verified',
  'audit.verify_fail': 'Verification failed — suspected tampering',
  'audit.event_count': '{count} events',

  'audit.disp.block': 'Blocked',
  'audit.disp.approve': 'Review',
  'audit.disp.sanitize': 'Sanitize',
  'audit.disp.allow': 'Allow',

  'audit.event.request_received': 'Request received',
  'audit.event.source_labeled': 'Source labeled',
  'audit.event.input_detected': 'Input inspected',
  'audit.event.model_forwarded': 'Forwarded to model',
  'audit.event.tool_intent_detected': 'Tool intent detected',
  'audit.event.policy_decided': 'Policy decision',
  'audit.event.tool_executed': 'Tool executed',
  'audit.event.tool_blocked': 'Tool blocked',
  'audit.event.tool_pending_approval': 'Pending approval',
}
