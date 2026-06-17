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


def _load_builtins() -> None:
    """显式注册所有内置实现:capabilities + 内置 adapter(model/audit)。"""
    load_builtin_capabilities()
    from .adapters.audit import memory_sink  # noqa: F401
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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
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

    pipeline = build_pipeline(cfg)  # 触发 _load_builtins,注册表此后含 scanner
    # 供应链扫描器经组装根注入 API(不入管线装配 —— 离线关切;adapters 不依赖 capabilities)。
    scanner = registry.create("scanner", "manifest")
    return build_api(pipeline, build_auth_bundle(settings), settings, upstream, store, scanner)
