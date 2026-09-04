"""Composition Root —— 在最外层把"具体实现"装配进管线并构建 API。

这是唯一允许"知道所有实现"的地方:导入 capabilities/adapters 触发注册,
再按 fulcrum.yml 从注册表取实现注入 SecurityPipeline。core 永远不知道它们的存在。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .capabilities import load_builtin_capabilities
from .config import Settings, load_capability_config
from .core.pipeline import SecurityPipeline
from .core.registry import registry
from .observability import configure_logging

if TYPE_CHECKING:
    from fastapi import FastAPI

    from .adapters.gateway import UpstreamForwarder


def _load_builtins() -> None:
    """显式注册所有内置实现:capabilities + 内置 adapter(model/audit)。"""
    load_builtin_capabilities()
    from .adapters.audit import memory_sink, sqlite_sink  # noqa: F401
    from .adapters.model import fake_client, openai_client  # noqa: F401


def build_pipeline(config: dict[str, Any] | None = None) -> SecurityPipeline:
    _load_builtins()
    cfg = config if config is not None else load_capability_config()

    # per-capability 参数注入:options.<注册名> → registry.create(kind, name, **那些参数)。
    # 统一约定,避免各队友各自发明配置侧门(env/硬编码);无条目=无参构造,向后兼容。
    opts: dict[str, Any] = cfg.get("options") or {}

    def make(kind: str, name: str) -> Any:
        return registry.create(kind, name, **(opts.get(name) or {}))

    return SecurityPipeline(
        labeler=make("labeler", cfg["labeler"]),
        detectors=[make("detector", name) for name in cfg["detectors"]],
        attributor=make("attributor", cfg["attributor"]),
        risk_scorer=make("risk_scorer", cfg["risk_scorer"]),
        chain_analyzer=make("chain_analyzer", cfg["chain_analyzer"]),
        policy=make("policy", cfg["policy"]),
        executor=make("executor", cfg["executor"]),
        tools={name: make("tool", name) for name in cfg["tools"]},
        audit=make("audit", cfg["audit"]),
        model_client=make("model", cfg["model"]),
    )


def _inject_judge_endpoint(cfg: dict[str, Any], settings: Settings) -> None:
    """语义层 LLM-judge 端点注入(fulcrum.yml 只管"启用"开关,端点/密钥**不入库**)。

    .env 配了模型(FULCRUM_MODEL_*)且 yml 未显式指定 endpoint 时,以 .env 为单一真源注入
    options.llm_judge —— 部署机各配各的;显式配置(如私有化本地 Ollama)优先,不被覆盖。
    """
    if "llm_judge" not in (cfg.get("detectors") or []):
        return
    judge_opts: dict[str, Any] = cfg.setdefault("options", {}).setdefault("llm_judge", {})
    if not judge_opts.get("endpoint") and settings.model_endpoint and settings.model_api_key:
        judge_opts.setdefault("endpoint", settings.model_endpoint)
        judge_opts.setdefault("model", settings.model_name)
        judge_opts.setdefault("api_key", settings.model_api_key)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    # 审计链封缄:配了 FULCRUM_AUDIT_HMAC_KEY 即让 hash-chain 走 HMAC(防内部人伪造/截断)。
    from .adapters.audit.hashchain import configure_hmac_key

    configure_hmac_key(settings.audit_hmac_key)
    cfg = load_capability_config(settings.capability_config)
    # 延迟导入,避免 core 测试时强依赖 fastapi。
    from .adapters.api import build_api
    from .adapters.auth import build_auth_bundle
    from .adapters.gateway import GatewayConfig, GatewayConfigStore, UpstreamForwarder

    # 上游接入配置:首启以 .env 的 upstream_agent_endpoint 作默认地址,
    # 之后以落盘配置为准(设置页可改、热加载)。
    seed = GatewayConfig(endpoint=settings.upstream_agent_endpoint, protocol="native")
    store = GatewayConfigStore(settings.gateway_config_path, seed=seed)
    upstream = UpstreamForwarder(store)

    # 审计 SQLite 库路径:Settings(.env 的 FULCRUM_AUDIT_DB_PATH)注入为单一真源,
    # 部署挂卷/测试 tmp 隔离都经此通道;fulcrum.yml 显式配了 options.sqlite.path 则以其优先。
    sqlite_path = cfg.setdefault("options", {}).setdefault("sqlite", {})
    sqlite_path.setdefault("path", settings.audit_db_path)

    _inject_judge_endpoint(cfg, settings)
    pipeline = build_pipeline(cfg)  # 触发 _load_builtins,注册表此后含 scanner
    # 供应链扫描器经组装根注入 API(不入管线装配 —— 离线关切;adapters 不依赖 capabilities)。
    scanner = registry.create("scanner", "manifest")
    app = build_api(pipeline, build_auth_bundle(settings), settings, upstream, store, scanner)
    _maybe_start_live_feed(app, pipeline, settings, upstream)
    return app


def _maybe_start_live_feed(
    app: FastAPI,
    pipeline: SecurityPipeline,
    settings: Settings,
    upstream: UpstreamForwarder | None = None,
) -> None:
    """演示开关:把攻击语料持续喂进运行中的管线,让首页 KPI / 实时事件页显示真实管线判定。

    默认关闭(生产/测试不受影响);仅内存审计 sink 下生效。开启置 FULCRUM_LIVE_FEED_ENABLED=1。
    `FULCRUM_LIVE_FEED_GATEWAY=1` 再走真网关流(政企智能体 :8800 在环,见 `live_feed`)。
    """
    if not settings.live_feed_enabled:
        return
    from .adapters.audit.memory_sink import InMemoryAuditSink

    if not isinstance(pipeline.audit, InMemoryAuditSink):
        return
    from .live_feed import LiveTrafficFeed

    feed = LiveTrafficFeed(
        pipeline,
        settings.live_feed_dataset,
        settings.live_feed_interval_seconds,
        settings.live_feed_max_sessions,
        upstream=upstream,
        gateway_mode=settings.live_feed_gateway,
    )
    # 用 Starlette Router 的生命周期钩子列表(跨版本稳定;build_api 未设自定义 lifespan)。
    app.router.on_startup.append(feed.start)
    app.router.on_shutdown.append(feed.stop)
