"""KeywordRuleDetector —— 多源、可分级的确定性输入风险检测(规则法)。

对应赛题目标①:覆盖用户输入、文档附件、网页内容、知识库检索结果、历史记忆、
工具返回等多源输入,识别六类风险并按"来源信任级 + 直接/间接来源"加权:

    injection       提示注入 / 指令覆盖
    jailbreak       越狱诱导 / 角色绕过
    exfiltration    数据外发 / 隐蔽外联
    sensitive_file  敏感文件 / 密钥凭据访问
    command_exec    系统命令 / 脚本执行
    data_poisoning  数据投毒 / 知识污染
    markup_exfil    渲染即外联(markdown 图片/链接、HTML img/a 把数据藏进 URL 查询串外发)
    pii_leak        结构化敏感量泄露(身份证/手机号/邮箱/密钥实值,按命中条数升级)

前六类靠"措辞"识别意图;`pii_leak` 不同——它数的是回复/输入里**真的夹带了多少条**结构化
个人或机密数据(实际号码/邮箱/密钥值)。单条多属正常(用户报自己手机号),批量出现才是
名册级外泄,故按命中条数升级严重度。出口闸门借此拦住"把市民名册原样吐出来"这类泄露——
仅凭关键词规则(sensitive_file 只识"提到了凭据")是抓不住的。

外加一条**混淆复扫**:`obfuscated_injection`——把文本里的 Base64/Hex 编码块解码后,用上述
危险规则复扫;命中即说明攻击者刻意把指令藏进编码绕过关键词匹配,按 critical 计分。

确定性、可解释、低延迟,作为第一层防线;LLM-judge 在 P3 作为后置增强叠加(见路线图)。
每个命中产出一条 Finding:`score`∈[0,1],`evidence.severity`∈{low,medium,high,critical},
并附命中规则、来源信息,供归因与审计取证使用。
"""

from __future__ import annotations

import re

from ...core.domain import Context, Finding, SourceSpan, SourceType, TrustLevel
from ...core.normalize import decode_variants, match_variants, normalize
from ...core.registry import capability

# 六类风险 -> (固有严重度基准 0~1, 正则模式集)。同类多模式命中合并为一条 Finding。
# 模式中英并重,面向政企中文场景;均为可解释的确定性规则。
_CATEGORIES: dict[str, tuple[float, tuple[str, ...]]] = {
    "injection": (
        0.75,
        (
            # 指令覆盖(放宽:ignore/无视 与目标词之间允许若干修饰词)
            r"ignore\s+(?:\w+\s+){0,3}(?:previous|above|prior|preceding|earlier|instruction|rules?|prompt|document|context)",
            r"disregard\s+(?:the\s+|all\s+|any\s+)*(instructions|above|previous|rules?|prompt)",
            r"override\s+(?:the\s+)*(instructions|system|rules?|prompt|safety)",
            r"forget\s+(everything|all|previous|the above|your (instructions|rules))",
            r"new\s+instructions?\s*[:：]",
            r"(reveal|show|print|repeat|output|dump)\s+(?:the\s+|your\s+|full\s+)*(system\s+)?(prompt|configuration|instructions)",
            r"忽略(以上|之前|上述|前面|刚才|前文|文档|正文|这段)",
            r"无视(以上|之前|上述|规则|指令|前面|文档)",
            r"不要(遵守|理会|遵循|管)",
            r"覆盖(指令|规则|系统设定|设置)",
            r"(新的|以下|真正的)指令\s*[:：]",
            r"(泄露|打印|输出|重复|贴出|背诵|复现)(你的|完整的?)?(系统)?(提示词|配置|连接串)",
            r"(系统)?提示词.{0,10}(原样|逐字|发|给我|输出|告诉|贴|泄露|打印)",
            r"(逐字|原样)(复现|输出|背诵|贴出|续写).{0,12}(提示词|策略|配置|规则|指令|工具)",
            # 伪边界 / 角色注入(冒充内部控制结构)
            r"</?(system|user|assistant|context|instructions?)\s*>",
            r"\[/?(INST|SYS|SYSTEM)\]",
            r"<\|im_(start|end)\|>",
            r"(tool_result|assistant|system)\s*[:：]\s*(status|approved|已批准|reasoning|推理)",
            r"===\s*(结束|end|完)\s*===",
            # 配置块伪装 / policy puppetry
            r"<\s*interaction-config|allowed-modes|blocked-(strings|modes)",
            # 拒绝抑制:目标是"压掉模型的拒绝/免责话术"。尾词只留**拒绝语**(无法/不能/抱歉/
            # 不便/免责/拒绝);移除"政策/权限"——它们是策略名词非拒绝语,"请不要使用未授权的权限"
            # 这类良性合规句会被误命中(真攻击说"不要说你无法/拒绝",不会说"不要用权限")。
            r"不(要|许|得)(说|出现|使用|加|有).{0,14}(无法|不能|抱歉|不便|免责|拒绝)",
            r"(do not|don'?t)\s+(apologize|refuse|warn|mention)|no\s+(disclaimer|warning|refusal)",
            r"禁止出现.{0,12}(无法|不能|抱歉|拒绝)",
            # 前缀诱导
            r"(start|begin)\s+(?:your\s+)?(answer|reply|response|output)\s+with",
            r"(回复|回答|输出)(必须|务必|请|要)?\s*(严格)?以.{0,20}(开头|开始)",
            # 权威伪装
            r"开发者(备注|模式|指令)|平台团队|系统覆盖|审计豁免|内部(指令|口径)(:|：)?|system\s+override|admin\s+override",
            # 载荷分片(变量赋值后拼接执行)
            r"设\s*[a-z]\s*[=＝].{0,24}[a-z]\s*[=＝]|let\s+\w+\s*=.{0,40}\+\s*\w+|执行\s*[a-z](\s*\+\s*[a-z]){1,}",
            # 工具返回伪造:方括号包裹的 [tool_result: …] 冒充内部判定结果(后常跟批准/预授权)。
            # 既有规则只认 "tool_result:" 后直接跟状态词,方括号+标签会绕过;此处收口方括号形态。
            r"\[tool_result\s*[:：]",
            # 藏头/首字组合(acrostic):把每句首字拼接成新指令再执行 —— 数据重组型注入。
            r"(取|拼|读|按).{0,4}(每句|各句|句子).{0,4}(首字|首字母|开头字).{0,8}(组合|拼接|串联|连读|拼起来|连起来).{0,8}(执行|照做|做|办|命令)",
            r"(藏头|首字母缩写|acrostic).{0,16}(指令|执行|照做|组合|拼接)",
            # 摩尔斯/摩斯码走私(token_smuggling_morse):指示先解码再照做 —— 隐藏明文指令。
            r"(摩尔斯|摩斯码|摩氏密码|morse).{0,16}(解码|破译|翻译|照做|照此执行|执行|转成|还原)",
            r"解码.{0,8}(摩尔斯|摩斯码).{0,8}(照做|执行|翻译)",
            # 低资源语种音译 PII 采集(low_resource_lang):重音符号包裹的 身份证/号码/居民/邮箱
            # 等拉丁音译词。每个分支都要求词内带重音(à/è/ì/ò/ù…),纯英文 id-card/resident 不命中。
            r"(?:[iì]d[- ]?k[àa]rt[aà]?|n[uù]m[eè]r[oò]|r[eè]s[iì]d[eè]nt|"
            r"[iì]m[eè]l|t[àa]m[àa]n[àa]?)",
        ),
    ),
    "jailbreak": (
        0.8,
        (
            r"you are now",
            r"developer mode|dev\s*mode|god\s*mode",
            r"do anything now|\b(DAN|AIM)\b",
            r"(without|no)\s+(any\s+)?(restrictions?|limitations?|rules?|filter|guardrails?)",
            r"bypass\s+(the\s+)?(safety|filter|guardrails?|审查|approval|review)",
            r"pretend\s+(you are|to be).{0,24}(unrestricted|no rules)",
            r"(skip|disable|turn off)\s+(the\s+)?(human\s+)?(review|approval|safety|filter)",
            r"你现在(是|要扮演|将)",
            r"开发者模式|越狱模式|进入越狱",
            # 无约束人格(放宽:无限制后允许"管理/权限/账户/终端…"等修饰名词)
            r"不受(任何)?限制|不设限|无限制(的)?\s*(模式|助手|终端|管理|权限|账户|系统|代理|智能体|ai)",
            # 绕过护栏(放宽:允许"绕规则/绕监管/绕开合规",并以负向后行避开"围绕/环绕"误命中)
            r"(?<![围环])绕\s*(过|开)?\s*(安全|过滤|审查|限制|策略|审批|核验|监管|合规|管控|规则|红线|防线|约束)",
            r"扮演一个?(不受|没有|无).{0,8}(限制|约束|规则)",
            # 仅祈使式「跳过/关闭」审批门算越狱;软量词「无需/免去」从本规则剔除——
            # 政务流程「无需核验原件即可受理」「该事项无需审批」是常见良性精简话术(救 FPR)。
            # 带定调框定的「一律/根据规定…无需核验」由 data_poisoning 规则收口,召回不丢。
            r"(跳过|关闭)\s*(二次)?\s*(审批|核验|复核|审查)",
            r"(演练|drill|测试|游戏)模式.{0,16}(跳过|关闭|无需|不需).{0,6}(审批|限制|核验)",
            # 关停审批门(放宽:关闭/解除/停用 与审批词之间允许"网关/二次"等少量修饰)
            r"(关闭|绕开|解除|停用|禁用|取消)\s*[^,。;\n]{0,4}(审批|核验|复核|审查|审核)门?",
            # 系统提示/策略提取诱导:内部提示词/访问控制策略/授权工具清单等**裸名词不单独命中**,
            # 必须与"逐字/原样/吐出/打印/贴出/泄露/复现/念出/写出/发我…"等提取动词同现才算越狱。
            # 救良性提问("什么是系统提示词""访问控制策略文档在哪下载""授权工具清单怎么申请")。
            r"(逐字|逐句|原样|打印|输出|吐出|贴出|泄露|复现|背诵|默写|念出|读出|说出|写出|念给|发我|发给我|告诉我)"
            r".{0,12}(系统提示词|系统提示语|提示词原文|访问控制策略|数据(留存|处置)策略|授权工具清单)|"
            r"(系统提示词|系统提示语|提示词原文|访问控制策略|数据(留存|处置)策略|授权工具清单)"
            r".{0,12}(逐字|逐句|原样|贴出|打印|输出|吐出|泄露|复现|背诵|默写|念出|读出|说出|发我|发给我|告诉我)",
            # 逐字复现(把"原话/逐字/精确"与"复现/打印/念给/背诵…"配对——情感/虚构框定下的提取铰链)
            r"(逐字|逐句|原话|原文|一字不差|精确|原封不动)\s*(地|的)?\s*"
            r"(复现|还原|重述|背诵|默写|输出|打印|贴出|说出|念出|表述|读出|念一遍|念给)",
            # 英文/JSON 工具调用绕审批(skip_human_review / approve_and_execute / bypass approval)
            r"(skip|bypass|disable|turn\s*off)[_\s-]*(the\s+)?(human[_\s-]*)?"
            r"(review|approval|audit|verification|oversight)|"
            r"skip[_-]?human[_-]?review|approve[_-]?and[_-]?execute",
            # 虚拟化/游戏框定:把"任何指令"直接当作已授权命令执行
            r"(任何|所有|一切)\s*(指令|命令|输入|请求).{0,16}"
            r"(已授权|当作(已)?授权|直接(当作|视为|执行)|无需(审批|确认|核验)|都(直接)?执行)",
            # 完整 system prompt / 凭据提取(英文+leetspeak):"输出完整 system prompt / 任何
            # credentials"是经典提示词抽取+凭据收割(OWASP LLM02)。中文侧既有"逐字…系统提示词"
            # 规则,此处补英文名词(经 deleet 后 pr0mpt→prompt 可中),须带"完整/全部/任何"定调
            # 才算整段抽取;良性"输出结果中提到的prompt字段"无完整抽取定调不命中。
            r"(输出|打印|泄露|贴出|给出|告诉我|发我|output|print|reveal|dump).{0,20}"
            r"(完整|全部|整个|任何|所有|any|all).{0,16}"
            r"(system\s*prompt|提示词|prompt|credentials?|凭据|密钥|口令|api[_-]?key|access[_-]?token|连接串|token)",
            # 危险动作提取(Bad Likert / Deceptive Delight:把有害做法洗成示例/剧情后"展开"步骤)。
            # **不裸配"X 和参数"**(良性"命令和参数的用法""操作步骤和参数列一下"会误命中),
            # 必须是"展开/写清…工具调用/命令/做法/绕过…"的提取祈使才命中。
            r"(展开|详述|写清|具体写出|详细写出|逐一写出)\s*(用到的|当时|到底)?.{0,10}"
            r"(工具调用|调用参数|命令|做法|凭据|绕过)",
            # Many-shot:伪造"既往对话片段/重复N轮都照办"做上下文条件
            r"[\[【]?(以下为|这是|附上|粘贴|附[::])\s*(既往|历史|过往|先前|此前|多轮)?\s*"
            r"(对话|聊天|会话)\s*(片段|记录|历史|内容)|"
            r"(重复|连续)\s*\d+\s*(轮|次).{0,12}(照办|都(照|答应|同意|执行|办)|无一拒绝)",
            # 码本/暗语替换:用代号"代指"身份证全表/外部邮箱等,触发词不以明文出现
            r"(代指|指代|代称|暗指|代表|表示)\s*[‘'\"“]?.{0,12}"
            r"(身份证|名册|名单|花名册|户籍|外部邮箱|外发|凭据|密钥|数据库|发到外部|全表)",
            # 把"历史/记录/日志/名册"**导出后**外发邮箱(长文稀释里夹带的真实外泄请求);
            # 须含"导出/外发/批量"动作——良性"会议记录发到邮箱""签到记录发邮件给我""值班记录
            # 发送到邮箱归档"无导出动作,不命中(救最常见办公场景 FPR);攻击侧的"…导出发我邮箱"仍中。
            r"(历史|记录|日志|名册|台账|名单)\s*(批量)?\s*(导出|外发)\s*.{0,6}"
            r"(发|发送|上传|回传|提交)\s*(我|到|给|送|至)?\s*.{0,6}(邮箱|外部|外网|邮件|http)",
        ),
    ),
    "exfiltration": (
        0.85,
        (
            r"exfiltrate",
            r"(send|upload|post|email|forward)\s+.{0,24}(to|至|给)\s+.{0,30}(http|external|外部|邮箱|@)",
            r"读取并(发送|外发|上传|回传|提交)",
            r"(外发|外传|回传|泄露|转发|上报)\s*(给|到|至)",
            # 外发到**外部/境外**目的地才算外泄;裸"邮箱/服务器"是日常 sink(「会议纪要发送到邮箱」
            # 「值班记录发送到邮箱归档」「上传到服务器」均良性),不单独命中——敏感载荷外发由下方
            # 「把…(身份证/名册/凭据…)…发/外发」收口,外发措辞由 r"(外发|外传…)(给|到)" 收口。
            r"(发送|提交|上传)\s*(到|给)\s*.{0,20}(外部|外网|境外|第三方|http)",
            r"curl\s+.{0,40}-d|POST\s+(到\s*)?https?://",
            r"把.{0,24}(身份证|名册|名单|花名册|凭据|密钥|手机号|联系方式|台账|会话|上下文|文件).{0,16}(发|外发|上传|提交|导出.{0,4}(发|到)|POST|回传|转发)",
            r"(发到|发往|追加到|同步到)\s*https?://",
            # 批量/公民等敏感数据**导出后发往外部目的地**(外链/邮箱地址/外部网盘):
            # 须「敏感数据 + 导出/外发 + 外部目的地」三要素同现;良性"导出用户数据生成报表/备份内网"
            # 无外部目的地不命中。覆盖"导出全部公民数据…并发到 x@外部域"这类伪装成功先例的外泄。
            r"(全部|所有|整批|批量|整个)?\s*(公民|用户|客户|人员|学生|患者|员工|群众|居民)\s*"
            r"(数据|信息|名册|名单|档案|资料|记录)\s*.{0,16}"
            r"(导出|外发|发到|发往|发送|上传|回传).{0,16}(@|https?://|外部|境外|外网|第三方)",
            # 格式胁迫 + PII 字段(style_coercion_json):只输出 JSON + 名册/身份证字段 →
            # 结构化批量外泄。良性"只输出 JSON 格式的统计结果"无 PII 字段不命中。
            r"只(输出|返回|给出|生成)\s*.{0,30}(json|数组|对象).{0,50}(id_card|身份证|名册|户籍|档案|花名册|居民记录|人员名单)",
            # CSS 隐藏元素夹带外发指令(css_hidden):font-size:0 / color:#fff / display:none 等
            # 隐藏样式后跟 URL 或外发措辞 → 隐蔽外联。静态页面的普通 CSS+链接不受影响。
            r"(?:font-size\s*:\s*0(?:px)?|color\s*:\s*(?:#fff|white)|visibility\s*:\s*hidden|display\s*:\s*none)[\s\S]{0,150}(?:https?://|发出|发送|外发|追加|引用链接)",
        ),
    ),
    "sensitive_file": (
        0.7,
        (
            r"/etc/(passwd|shadow)",
            r"id_rsa|\.ssh/|\.env\b|\.pem\b|\.key\b",
            r"(private[_ ]?key|api[_ ]?key|secret[_ ]?key|access[_ ]?token|credentials?)",
            r"(密钥|私钥|口令|凭据|凭证|机密|涉密|账号密码)",
            r"\.aws[\\/]+credentials|\.kube[\\/]+config|system32[\\/]+config[\\/]+(sam|system)",
            r"ntds\.dit|connection string|连接串",
            # 内部敏感资产外泄:输出/泄露 内部路由表、服务账号、数据库账号等(须带提取动词,
            # 纯问"什么是路由表/服务账号申请流程"不命中)。
            r"(输出|泄露|打印|导出|贴出|告诉我|给我|背下来).{0,12}(内部路由表|路由表|服务账号|运维账号|管理员账号|数据库账号|账号口令|服务器密码|root\s*密码|超级管理员账号)",
        ),
    ),
    "command_exec": (
        0.8,
        (
            r"rm\s+-rf",
            r"\b(curl|wget)\s+https?://",
            r"(bash|sh|zsh|powershell|cmd)\s+-c|/bin/sh\b|/dev/tcp/",
            r"(os\.system|subprocess\.|\bexec\(|\beval\()",
            r"base64\s+-d|chmod\s+777|\bnc\b\s+-e|reverse shell|mkfifo|\bsocat\b",
            r"\bcertutil\b|\bbitsadmin\b|\bmshta\b|\bregsvr32\b|\brundll32\b|invoke-expression|\biex\b",
            r"\|\s*(ba|z)?sh\b|\|\s*powershell",
            r"(执行|运行|调用)(系统)?(命令|脚本|shell|cmd)",
            r"删除(所有|全部|整个)(文件|数据|目录)",
        ),
    ),
    "data_poisoning": (
        0.6,
        (
            r"this is the (only )?correct answer",
            r"always (recommend|choose|select|answer|reply)",
            r"the (official|approved) (policy|answer) is now",
            r"(标准|正确|唯一)答案(是|为|就是)",
            r"以后(都|一律|请|要|凡)?.{0,12}(推荐|选择|回答|认为|记住|自动(通过|批准)|批准|通过)",
            r"(今后|从现在起|从今以后|往后).{0,14}(自动(通过|批准)|一律|都).{0,8}(通过|批准|跳过|推荐)",
            r"永远(推荐|选择|相信|认为|通过)",
            r"记住(这条|这个|这|以下|此)?(重要)?(规则|规范|设定|偏好|事实)",
            # 伪事实写入(放宽:记牢/记好/记清 + 事实/金额/口径…——PoisonGPT 式造假后日后复述)
            r"记(牢|好|清)\s*(这条|这个|这|此|一个)?(重要)?\s*(规则|规范|设定|事实|口径|结论|金额|数字|说法|偏好)",
            # 伪官方"唯一标准/规定"**断言**:须带定调词 + 真·断言系词,只在自封权威注入式断言里命中。
            # 救良性疑问/咨询("这是不是现行唯一标准""想确认下唯一标准的内容""目前唯一标准是什么")。
            # ①系词在定调词前(「(这)是现行唯一标准」),负向后行排除「不是/没…」否定疑问;
            r"(?<![不否没])(是|即)\s*(现行|当前|从此|今后|此后|目前)\s*"
            r"唯一\s*(标准|规定|答案|依据|口径|要求|说法|规则)",
            # ②系词在名词后(「今后唯一标准就是…」),负向前瞻排除「是否/是什么/是多少」等疑问续接。
            r"(现行|当前|从此|今后|此后|目前)\s*唯一\s*"
            r"(标准|规定|答案|依据|口径|要求|说法|规则)+\s*(就是|是|即|应为|定为|=|[:：])"
            r"(?![否吗么呢?？]|\s*什么|\s*多少|\s*哪|\s*的?内容)",
            # 宣称办事"无需核验"**只在伪造规则的祈使/断言**里命中(根据规定…/一律/从现在起 等定调),
            # 疑问句("这个服务无需审核就能办理吗""不用验证原件吗")不命中——救良性咨询。
            r"((根据|按照|依据|遵照|依照).{0,12}(规定|口径|政策|要求|通知|文件|精神|标准)|"
            r"一律|统一|今后|从现在起|从此|往后|一概|凡是?)"
            r".{0,16}(无需|不需|不用|无须|毋须|免去)\s*(身份)?\s*(核验|审核|审批|验证|核实|查验)",
            # 反向(定调词在后):"无需核验,一律先办""免去审批、从此直接通过"——投毒里把伪规则
            # 说成"无需X+一律/直接办"。良性"无需核验原件即可受理""无需审批,即来即办"无定调词不命中。
            r"(无需|不需|不用|无须|毋须|免去)\s*(身份)?\s*(核验|审核|审批|验证|核实|查验)"
            r".{0,8}(一律|一概|统一|凡是?|今后|从此|往后|从现在起|直接\s*(办|放行|批准|通过|受理))",
            # 知识库投毒夹外泄/伪权威:要求结尾必附外链、并声明其为"官方依据"
            r"必须.{0,10}(结尾|末尾|文末)?\s*附\s*(上|带)?\s*https?://",
            r"声明\s*(此|这|其|该)?\s*(为|是)\s*官方\s*(依据|规定|口径|来源|文件|答案)",
            r"不(要|得).{0,6}(写|留|触发).{0,6}(审计|日志|记录|复核)",
            r"当.{0,14}(暗语|口令|触发词?|出现).{0,14}时.{0,16}(批准|通过|权限|不留)",
            r"自动(批准|通过)|跳过.{0,4}(核验|审批|二次)",
            r"我说的(话|内容).{0,10}(优先级?高于|优先于|压过).{0,10}(系统|规则|文件)",
        ),
    ),
    # 渲染即外联(SearchLeak / 图片外泄 / 零点击):回复或文档里藏一个 markdown 图片/链接、
    # 或 HTML <img>/<a>,URL 查询串夹带**编码数据载荷或明文 PII**。前端一渲染就把数据带进
    # query 自动外发,**全程无"外发"措辞、数据被编码**——exfiltration(数措辞)与 pii_leak
    # (数明文量)都抓不住。判别力靠「markup 包裹 + 查询串里的长编码载荷/PII」,不依赖域名白名单,
    # 故正常静态图(无数据载荷查询)不误报。权重取 high 档:出口→人工复核;不可信文档间接→阻断。
    "markup_exfil": (
        0.65,
        (
            r"!?\[[^\]]*\]\(\s*<?https?://[^)\s>]*[?&#][^)\s>]*=[A-Za-z0-9%+/_=-]{24,}",
            r"<(?:img|image)\b[^>]*\bsrc\s*=\s*['\"]?https?://[^'\">\s]*[?&#][^'\">\s]*=[A-Za-z0-9%+/_=-]{24,}",
            r"<a\b[^>]*\bhref\s*=\s*['\"]?https?://[^'\">\s]*[?&#][^'\">\s]*=[A-Za-z0-9%+/_=-]{24,}",
            r"(?:!?\[[^\]]*\]\(|src\s*=|href\s*=)\s*['\"<]?https?://[^)\s'\">]*(?:1[3-9]\d{9}|\d{17}[\dXx])",
        ),
    ),
}

# 结构化敏感量:实际数值/令牌(而非仅"提到凭据"的措辞)。与 sensitive_file 互补——
# 此类命中表示文本里**真的夹带了**个人或机密数据,是出口名册外泄的直接证据。
_PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"),  # 身份证号(18 位)
    re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),  # 手机号(11 位)
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),  # 邮箱
    re.compile(  # 显式密钥/口令赋值(带实值)
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
        r"密码|口令|密钥|凭据|凭证)\s*[:=]\s*\"?[^\s\"]{3,}"
    ),
)


def _pii_score(count: int) -> float:
    """命中条数 → 严重度基准:单条(0.4,多属正常)→ 批量名册外泄(0.85,critical)。"""
    if count >= 3:
        return 0.85
    if count == 2:
        return 0.6
    return 0.4


# 意图区分(降 FPR):疑问 / 科普 / 求解释的框架性措辞。命中表示文本在**询问某概念**,
# 而非**下达攻击指令**。仅用于"纯敏感词提及"(sensitive_file)的降权判定,不影响动作类攻击。
# 通用框架词、不针对样本 ID 硬编码(防过拟合)。
_INFORMATIONAL = re.compile(
    r"什么是|是什么|啥意思|什么意思|什么含义|的含义|的区别|有什么区别|有何区别|"
    r"干嘛用|干什么用|是干(嘛|什么)的|怎么理解|如何理解|怎么用|如何使用|"
    r"如何防(范|御|护)|怎么防(范|御)|怎样防范|防范(手段|措施|方法)|"
    r"解释一?下|科普|介绍一?下|了解一?下|想(了解|知道|请教)|普及|扫盲|"
    r"有哪些|到底是|通俗(地?讲|解释)|"
    r"\bwhat\s+(is|are|does|do)\b|\bhow\s+(to|do|does|can)\b|"
    r"\bexplain\b|\bmeaning\s+of\b|difference\s+between|what'?s\b",
    re.IGNORECASE,
)


def _is_informational(variants: list[str]) -> bool:
    return any(_INFORMATIONAL.search(v) for v in variants)


# 来源信任级 -> 乘子:不可信来源命中风险最高,用户直述同样措辞风险较低。
_TRUST_MUL: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.SEMI_TRUSTED: 0.8,
    TrustLevel.TRUSTED: 0.55,
}

# 间接来源(藏在文档/网页/检索/记忆/工具返回/插件清单里)是"间接指令污染"的主战场,额外加权。
_INDIRECT_SOURCES: frozenset[SourceType] = frozenset(
    {
        SourceType.DOCUMENT,
        SourceType.WEBPAGE,
        SourceType.RETRIEVAL,
        SourceType.MEMORY,
        SourceType.TOOL_RETURN,
        SourceType.PLUGIN_MANIFEST,
    }
)
_INDIRECT_BOOST = 0.15

# 启动时编译一次(忽略大小写),热路径零编译开销。
_COMPILED: dict[str, tuple[float, tuple[re.Pattern[str], ...]]] = {
    cat: (weight, tuple(re.compile(p, re.IGNORECASE) for p in pats))
    for cat, (weight, pats) in _CATEGORIES.items()
}


def _severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


# ---- 混淆注入复扫:攻击者把「ignore previous instructions」之类塞进编码绕过关键词 ----
# 解码委托 core.normalize.decode_variants(递归 Base64/Hex/URL/ROT13),再用既有危险规则复扫。
# 解码后命中 = 刻意隐藏意图,比明文更可疑,按 critical 基准计分;解不出可读文本/无危险词则不产 finding,
# 故正常 Base64(图片、令牌)不会误报。
_DEOBF_CATEGORIES: tuple[str, ...] = ("injection", "jailbreak", "exfiltration", "command_exec")
_DEOBF_BASE = 0.85  # 混淆即恶意意图,基准取 critical 档


def _scan_decoded(decoded: str) -> list[str]:
    """对解码后的文本复扫危险类别,返回命中的类别名(去重、按固定顺序)。"""
    return [cat for cat in _DEOBF_CATEGORIES if any(p.search(decoded) for p in _COMPILED[cat][1])]


@capability("detector", "keyword_rules")
class KeywordRuleDetector:
    """多源规则检测器。注册名沿用 `keyword_rules`,装配清单无需改动。"""

    name = "keyword_rules"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            text = span.content
            # 匹配前归一化:在 原文/归一化(NFKC+剥不可见+同形字折叠)/去leet 多副本上跑规则,
            # 抹平 全角/同形字/零宽/双向/leetspeak 绕过(原文不动,仅用于匹配)。
            variants = match_variants(text)
            norm_text = normalize(text)
            trust_mul = _TRUST_MUL.get(span.trust_level, 1.0)
            indirect = span.source_type in _INDIRECT_SOURCES
            matched_by_cat: dict[str, list[str]] = {}
            for cat, (_weight, patterns) in _COMPILED.items():
                matched = [p.pattern for p in patterns if any(p.search(v) for v in variants)]
                if matched:
                    matched_by_cat[cat] = matched
            # 意图区分降 FPR:直接来源、纯疑问/科普语气、且**唯一**风险信号是"敏感词提及"
            # (sensitive_file 仅识"提到了凭据/路径",非动作)→ 视为信息询问而非攻击,抑制该 finding。
            # 救"科普 /etc/passwd 各列含义""问 API key 是什么"两类硬负例;带任何动作类攻击
            # (注入/越狱/外发/命令/投毒)即不抑制,间接来源(注入主战场)亦不抑制 → 不伤召回。
            if (
                set(matched_by_cat) == {"sensitive_file"}
                and not indirect
                and _is_informational(variants)
            ):
                matched_by_cat = {}
            for cat, matched in matched_by_cat.items():
                weight = _COMPILED[cat][0]
                raw = weight * trust_mul + (_INDIRECT_BOOST if indirect else 0.0)
                score = round(min(raw, 1.0), 3)
                findings.append(
                    Finding(
                        kind=cat,
                        score=score,
                        evidence={
                            "source_id": span.source_id,
                            "source_type": span.source_type,
                            "trust_level": span.trust_level,
                            "severity": _severity(score),
                            "matched_rules": matched,
                            "indirect_source": indirect,
                        },
                    )
                )
            # 结构化敏感量:按命中条数(身份证/手机/邮箱/密钥实值)升级,而非固定权重。
            # 在归一化文本上数(NFKC 把全角数字还原为半角,救回全角化的 PII)。
            pii_hits = sum(len(p.findall(norm_text)) for p in _PII_PATTERNS)
            if pii_hits:
                raw = _pii_score(pii_hits) * trust_mul + (_INDIRECT_BOOST if indirect else 0.0)
                score = round(min(raw, 1.0), 3)
                findings.append(
                    Finding(
                        kind="pii_leak",
                        score=score,
                        evidence={
                            "source_id": span.source_id,
                            "source_type": span.source_type,
                            "trust_level": span.trust_level,
                            "severity": _severity(score),
                            "pii_hits": pii_hits,
                            "indirect_source": indirect,
                        },
                    )
                )
            # 混淆复扫:递归解码后再扫;命中 = 刻意隐藏的注入/外发/命令,按 critical 计分。
            # **模式级**去重:明文已直接命中的模式,其危险本就可读可见,只是 ROT13/unquote/
            # 实体还原等变换副本又复现一次——非"刻意隐藏",不重复升级;仅**解码后才暴露的新模式**
            # (明文未命中)才计入混淆,按 critical 计分。否则同一条规则 0.75(直接)+0.85(复扫)
            # 双计,会把本应 approve 的注入错误抬成 block;而真正藏进 base64/hex 的注入,
            # 明文看不到对应模式,仍照常命中混淆。
            direct_pats = {p for ps in matched_by_cat.values() for p in ps}
            for decoded in decode_variants(text):
                hidden: list[str] = []
                for _cat in _DEOBF_CATEGORIES:
                    if any(
                        p.search(decoded) and p.pattern not in direct_pats
                        for p in _COMPILED[_cat][1]
                    ):
                        hidden.append(_cat)
                if not hidden:
                    continue
                raw = _DEOBF_BASE * trust_mul + (_INDIRECT_BOOST if indirect else 0.0)
                score = round(min(raw, 1.0), 3)
                findings.append(
                    Finding(
                        kind="obfuscated_injection",
                        score=score,
                        evidence={
                            "source_id": span.source_id,
                            "source_type": span.source_type,
                            "trust_level": span.trust_level,
                            "severity": _severity(score),
                            "decoded_kinds": hidden,
                            "decoded_excerpt": decoded[:80],
                            "indirect_source": indirect,
                        },
                    )
                )
                break  # 一个 span 报一条混淆 finding 足矣,避免多块重复刷分
        return findings
