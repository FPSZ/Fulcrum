"""Composition Root —— 在最外层把"具体实现"装配进管线并构建 API。

这是唯一允许"知道所有实现"的地方:导入 capabilities/adapters 触发注册,
再按 fulcrum.yml 从注册表取实现注入 SecurityPipeline。core 永远不知道它们的存在。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .capabilities import load_builtin_capabilities
from .config import Settings, load_capability_config, normalize_detector_zones
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
    # 直接调用 build_pipeline 的评测/集成代码也必须经过同一份 schema 校验；不能信任
    # 调用方可能预填的派生字段 detector_zones。
    detector_zones = normalize_detector_zones(cfg["detectors"])

    def make(kind: str, name: str) -> Any:
        return registry.create(kind, name, **(opts.get(name) or {}))

    # 分区配置中的每个名称都在构建期实例化，拼错的检测器不会等到某个流量路径才暴露。
    detector_names = dict.fromkeys(name for names in detector_zones.values() for name in names)
    detectors_by_name = {name: make("detector", name) for name in detector_names}

    return SecurityPipeline(
        labeler=make("labeler", cfg["labeler"]),
        # P_a-2 前仍按旧的全局检测逻辑运行；这里保留扁平配置的调用顺序和重复项语义。
        detectors=[
            detectors_by_name[name]
            for name in (cfg["detectors"] if isinstance(cfg["detectors"], list) else detector_names)
        ],
        detector_zones={
            zone: [detectors_by_name[name] for name in names]
            for zone, names in detector_zones.items()
        },
        attributor=make("attributor", cfg["attributor"]),
        risk_scorer=make("risk_scorer", cfg["risk_scorer"]),
        chain_analyzer=make("chain_analyzer", cfg["chain_analyzer"]),
        policy=make("policy", cfg["policy"]),
        executor=make("executor", cfg["executor"]),
        tools={name: make("tool", name) for name in cfg["tools"]},
        audit=make("audit", cfg["audit"]),
        model_client=make("model", cfg["model"]),
    )


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
    from .adapters.security_config import SecurityConfigStore

    # 上游接入配置:首启以 .env 的 upstream_agent_endpoint 作默认地址,
    # 之后以落盘配置为准(设置页可改、热加载)。
    seed = GatewayConfig(endpoint=settings.upstream_agent_endpoint, protocol="native")
    store = GatewayConfigStore(settings.gateway_config_path, seed=seed)
    upstream = UpstreamForwarder(store)

    # 分级安全配置以静态能力清单为基线，首启默认标准档；以后从持久化配置恢复并热加载。
    security_store = SecurityConfigStore(settings.security_config_path)
    security_config = security_store.load()
    pipeline = build_pipeline(
        security_config.apply_to(cfg)
    )  # 触发 _load_builtins,注册表此后含 scanner
    # 供应链扫描器经组装根注入 API(不入管线装配 —— 离线关切;adapters 不依赖 capabilities)。
    scanner = registry.create("scanner", "manifest")
    app = build_api(
        pipeline,
        build_auth_bundle(settings),
        settings,
        upstream,
        store,
        scanner,
        security_store=security_store,
        capability_config=cfg,
        pipeline_factory=build_pipeline,
    )
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
