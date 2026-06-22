import { createBoolPref } from './bool-pref'

/**
 * 「事件对话展示」合规开关(默认开,内容已脱敏)。
 *
 * 隐私设计:对话文本在**后端管线落库前即脱敏**(`core/redaction`,身份证/手机/邮箱/密钥打码),
 * 且枢衡私有化部署、数据不出域。控制台是否在事件详情里呈现这段(已脱敏的)对话,由**企业管理员**
 * 按自身合规要求决定——严格场景可关闭。能力我们提供、默认安全,用与不用是控制者(企业)的选择。
 */
export const { use: useConversationDisplay } = createBoolPref('fulcrum.conv_display', true)
