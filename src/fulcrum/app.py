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
    from .adapters.model import fake_client  # noqa: F401


def build_pipeline(config: dict[str, Any] | None = None) -> SecurityPipeline:
    _load_builtins()
    cfg = config if config is not None else load_capability_config()
    return SecurityPipeline(
        labeler=registry.create("labeler", cfg["labeler"]),
        detectors=[registry.create("detector", name) for name in cfg["detectors"]],
        attributor=registry.create("attributor", cfg["attributor"]),
        risk_scorer=registry.create("risk_scorer", cfg["risk_scorer"]),
        chain_analyzer=registry.create("chain_analyzer", cfg["chain_analyzer"]),
        policy=registry.create("policy", cfg["policy"]),
        executor=registry.create("executor", cfg["executor"]),
        tools={name: registry.create("tool", name) for name in cfg["tools"]},
        audit=registry.create("audit", cfg["audit"]),
        model_client=registry.create("model", cfg["model"]),
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    cfg = load_capability_config(settings.capability_config)
    # 延迟导入,避免 core 测试时强依赖 fastapi。
    from .adapters.api import build_api
    from .adapters.auth import build_auth_bundle

    return build_api(build_pipeline(cfg), build_auth_bundle(settings), settings)
