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

    # 装配清单路径(None 用包内默认 fulcrum.yml)
    capability_config: str | None = None

    # 审计/运行目录
    audit_db_path: str = "data/runtime/fulcrum.sqlite"

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
