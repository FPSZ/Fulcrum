"""运行时设置 —— 从环境变量 / .env 加载,类型化注入,不到处读 os.environ。"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FULCRUM_", env_file=".env", extra="ignore")

    # 服务
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"

    # 模型:OpenAI 兼容端点(桩用 fake;openai 适配器读取以下三项连真实模型)
    model_endpoint: str = "http://127.0.0.1:11434/v1"
    model_api_key: str = ""
    model_name: str = "mimo-v2.5-pro"

    # 被保护的企业智能体:网关放行后把请求转发到此。首启用作上游配置的默认地址。
    # 运行期真正生效的接入配置存于 gateway_config_path(设置页可改、热加载),不再依赖本项。
    upstream_agent_endpoint: str = "http://127.0.0.1:8800"
    # 网关数据面鉴权:/gateway/chat 是企业集成调用的**数据面**端点(非控制台会话)。设了本项
    # 则要求请求头 X-Fulcrum-Gateway-Key 匹配,挡未授权直连 / 开放中继;留空(默认)= 不校验
    # (本地/演示便利)。**生产务必设置**(见 deploy 环境注入)。
    gateway_api_key: str = ""
    # 网关上游接入配置落盘路径(JSON);Docker 部署挂卷于 data/runtime 即持久化。
    gateway_config_path: str = "data/runtime/gateway.json"
    # 控制台实例元信息落盘路径(JSON);同上挂卷即持久化。
    console_settings_path: str = "data/runtime/console.json"
    # 分级安全预设与按区覆盖落盘路径(JSON);保存后热替换运行中的检测器配置。
    security_config_path: str = "data/runtime/security.json"
    # 操作助手多轮对话记忆目录(一会话一文件);落盘故重启不丢,挂卷即持久化。
    conversation_dir: str = "data/runtime/conversations"
    # 操作助手模型接入配置落盘路径(JSON;协议/端点/密钥/模型名);设置页可改、热加载。
    assistant_model_config_path: str = "data/runtime/model.json"

    # 装配清单路径(None 用包内默认 fulcrum.yml)
    capability_config: str | None = None

    # 评测报告路径:`python -m fulcrum.eval` 的最近一次产物;评测页只读展示,无则回退演示
    eval_report_path: str = "docs/eval/results/latest.json"

    # 供应链:待扫描的组件 manifest 目录(供应链页只读展示其静态扫描评级)
    supply_manifest_dir: str = "samples/supplychain"

    # 前端静态资源目录(生产:指向已构建的 console/dist);留空则只提供 API
    frontend_dir: str = ""

    # ── 实时流量驱动(仅演示/可视化)──────────────────────────────────
    # 把攻击语料库持续喂进运行中的管线(真跑 screen_input/evaluate_intent/screen_output),
    # 让首页 KPI / 实时事件页显示**真实管线判定**而非演示 seed。默认关闭,生产/测试不受影响;
    # 演示时置 FULCRUM_LIVE_FEED_ENABLED=1 开启。仅在内存审计 sink 下生效。
    live_feed_enabled: bool = False
    live_feed_dataset: str = "samples/eval/corpus"
    live_feed_interval_seconds: float = 2.0
    live_feed_max_sessions: int = 300
    # gateway 模式:input 级样例走**真网关流**(screen_input→放行才转发 MiMo→screen_output),
    # 政企智能体(:8800,真连 MiMo)在环,首页/事件/网关页显示真实端到端活动;
    # 默认 False = 纯检测管线回放(不调模型,零 token 成本)。
    live_feed_gateway: bool = False

    # 审计/运行目录
    audit_db_path: str = "data/runtime/fulcrum.sqlite"
    # 审计链封缄密钥(可选):设了则 hash-chain 走 HMAC-SHA256,拿到库写权限者无密钥也无法
    # 伪造合法链(防内部人篡改/截断)。留空=裸 SHA256(防误改不防蓄意)。**生产建议设**高熵串。
    audit_hmac_key: str = ""

    # ── 登录鉴权(账号口令 + 服务端会话)─────────────────────────────
    # 用户/会话库(SQLite,与审计库分离,便于单独备份/审计)
    auth_db_path: str = "data/runtime/auth.sqlite"
    # 会话绝对有效期(小时);超过则强制重新登录
    session_ttl_hours: int = 12
    # 会话 Cookie:HttpOnly 恒开;Secure 在 TLS 反代后置 true;SameSite=strict 防 CSRF
    session_cookie_name: str = "fulcrum_session"
    session_cookie_secure: bool = False
    session_cookie_samesite: str = "strict"
    # 暴力破解防护:连续失败次数达阈值后锁定账号一段时间
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    # 首次启动引导管理员:库内无用户时据此创建;口令留空则随机生成并打印一次
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""
