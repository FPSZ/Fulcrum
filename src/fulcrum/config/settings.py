"""运行时设置 —— 从环境变量 / .env 加载,类型化注入,不到处读 os.environ。"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FULCRUM_", env_file=".env", extra="ignore")

    # 服务
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"

    # 模型(M0 用桩,不实际连接)
    model_endpoint: str = "http://127.0.0.1:11434/v1"
    model_api_key: str = ""

    # 装配清单路径(None 用包内默认 fulcrum.yml)
    capability_config: str | None = None

    # 审计/运行目录
    audit_db_path: str = "data/runtime/fulcrum.sqlite"
