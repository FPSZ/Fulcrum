import type { MessageKey } from '../../index'

// AI Operations Assistant.
export const assistant: Partial<Record<MessageKey, string>> = {
  // Empty state (hero)
  'assistant.hero.title': 'What can I help you with?',
  'assistant.cap.query': 'Data query',
  'assistant.cap.handle': 'Task handling',
  'assistant.cap.navigate': 'Navigate',
  'assistant.cap.settings': 'Change settings',
  // Empty-state suggestions
  'assistant.suggest.overview': 'Show me the security overview',
  'assistant.suggest.events': 'What events were blocked recently?',
  'assistant.suggest.approvals': 'List accounts pending approval',
  'assistant.suggest.gateway': 'Change the upstream gateway name',
  // Footer note
  'assistant.disclaimer': 'AI can make mistakes — please verify the results',

  // Composer
  'assistant.composer.placeholder': 'Give the assistant a task…',
  'assistant.composer.send': 'Send',
  'assistant.composer.hint.ready': 'Enter to send · Shift+Enter for a new line',
  'assistant.composer.hint.unconfigured': 'Model not configured · open settings on the left',
  'assistant.composer.hint.contact_admin': 'Model not configured · contact your admin',
  'assistant.composer.settings': 'Model settings',
  'assistant.composer.settings.configure': 'Model not configured — click to configure',
  'assistant.composer.settings.no_perm': 'Model settings (permission required)',
  'assistant.composer.settings.no_perm_title': 'Configuring the model requires permission — contact your admin',

  // Conversation sidebar
  'assistant.sidebar.title': 'Conversations',
  'assistant.sidebar.expand': 'Expand conversations',
  'assistant.sidebar.collapse': 'Collapse conversations',
  'assistant.sidebar.new': 'New conversation',
  'assistant.sidebar.history': 'History',
  'assistant.sidebar.empty': 'No past conversations',
  'assistant.sidebar.empty.hint': 'Start a conversation and it will be saved here',
  'assistant.sidebar.untitled': 'New chat',
  'assistant.sidebar.delete': 'Delete conversation',

  // Message turn
  'assistant.turn.blocked': 'Blocked by the security gateway',
  'assistant.turn.trace': 'Execution trace · {n} steps',
  'assistant.turn.error': 'Error: {msg}',

  // Context-compression notice
  'assistant.compress.title': 'Earlier context was automatically compressed',
  'assistant.compress.desc': 'The conversation is long, so earlier content was summarized to keep the context going.',

  // Navigation command feedback
  'assistant.nav.events': 'Switched to Live Events',
  'assistant.nav.settings': 'Opened Settings',
  'assistant.nav.opened': 'Opened "{label}" for you',

  // Model-not-configured block
  'assistant.model.unconfigured': 'The model is not configured yet',
  'assistant.model.unconfigured.configure': 'Please configure the model protocol, endpoint, and key in settings first.',
  'assistant.model.unconfigured.contact': 'Please ask an admin to configure the AI model before using this.',

  // Proposal card (write actions)
  'assistant.proposal.confirm': 'Confirm & run',
  'assistant.proposal.executing': 'Running…',
  'assistant.proposal.cancelled': 'Cancelled',
  'assistant.proposal.undo': 'Undo',
  'assistant.proposal.undo_with': 'Undo ({preview})',
  'assistant.proposal.done': 'Done',
  'assistant.proposal.undoing': 'Undoing…',
  'assistant.proposal.undone': 'Undone',
  'assistant.proposal.bool.yes': 'Yes',
  'assistant.proposal.bool.no': 'No',

  // Proposal execution result (toast)
  'assistant.toast.executed': 'Executed',
  'assistant.toast.execute_failed': 'Execution failed',
  'assistant.toast.undone': 'Undone',
  'assistant.toast.undo_failed': 'Undo failed',

  // Approval card
  'assistant.approval.badge': 'Requires admin approval',
  'assistant.approval.reason': 'Approval reason',
  'assistant.approval.reason.placeholder': 'Explain why this step is needed so an admin can decide…',
  'assistant.approval.file': 'Submit for approval',
  'assistant.approval.retry': 'Retry submission',
  'assistant.approval.skip_hint': 'Skip and no ticket is created',
  'assistant.approval.filing': 'Submitting…',
  'assistant.approval.filed': 'Submitted for approval — an admin is handling it',
  // Approval request result (toast)
  'assistant.approval.toast.filed': 'Approval request submitted',
  'assistant.approval.toast.filed_desc': 'It is now under "Live Events · Pending review", where an admin will handle it.',
  'assistant.approval.toast.failed': 'Submission failed',

  // Model settings dialog
  'assistant.settings.title': 'AI model access',
  'assistant.settings.readonly': 'You do not have permission to configure this; the following is read-only. Contact a super admin or system admin.',
  'assistant.settings.protocol': 'Protocol',
  'assistant.settings.preset': 'Quick preset',
  'assistant.settings.preset.local': 'Local',
  'assistant.settings.endpoint': 'Endpoint',
  'assistant.settings.model': 'Model',
  'assistant.settings.api_key': 'API key (optional for local models)',
  'assistant.settings.api_key.ph_local': 'Optional for local models',
  'assistant.settings.api_key.ph_set': 'Configured {masked} (leave blank to keep)',
  'assistant.settings.timeout': 'Timeout (s)',
  'assistant.settings.verify_tls': 'Verify TLS certificate',
  'assistant.settings.test': 'Test connection',
  // Protocol metadata
  'assistant.settings.endpoint.ph_openai': 'https://api.openai.com/v1 or http://127.0.0.1:1234/v1',
  'assistant.settings.proto.openai': 'OpenAI-compatible',
  'assistant.settings.proto.openai.hint': 'Covers OpenAI / DeepSeek / Kimi / MiMo, plus the /v1 endpoints of local vLLM / LM Studio / llama.cpp / Ollama',
  'assistant.settings.proto.ollama': 'Ollama native',
  'assistant.settings.proto.ollama.hint': 'Most common for on-premise; usually no key required',
  'assistant.settings.proto.anthropic': 'Anthropic',
  'assistant.settings.proto.anthropic.hint': 'Claude /v1/messages',
  // Save result (toast)
  'assistant.settings.toast.saved': 'Model configuration saved',
  'assistant.settings.toast.saved_desc': 'Applied with hot reload — you can start chatting now.',
  'assistant.settings.toast.save_failed': 'Save failed',

  // Streaming request failure
  'assistant.error.request_failed': 'Assistant request failed',

  // Risk levels
  'assistant.risk.read_only': 'Read-only',
  'assistant.risk.normal': 'Normal',
  'assistant.risk.high': 'High-risk',

  // Tool kinds (trace labels / sidebar groups)
  'assistant.kind.ui': 'UI',
  'assistant.kind.read': 'Query',
  'assistant.kind.write': 'Action',

  // Quick example intents
  'assistant.intent.overview': 'Open the security overview for me',
  'assistant.intent.blocked_events': 'Show only blocked live events',
  'assistant.intent.disable_policy': 'Temporarily disable policy POL-014',
}
