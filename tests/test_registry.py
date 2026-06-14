"""注册表:内置能力均已注册。"""

from __future__ import annotations

from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.core.registry import registry

load_builtin_capabilities()


def test_builtin_capabilities_registered() -> None:
    assert "passthrough" in registry.names("labeler")
    assert "keyword_rules" in registry.names("detector")
    assert "allow_all" in registry.names("policy")
    assert "echo" in registry.names("tool")
    assert "echo" in registry.names("executor")
    assert "noop" in registry.names("scanner")


def test_unknown_capability_raises() -> None:
    from fulcrum.core.errors import ConfigError

    try:
        registry.create("detector", "does_not_exist")
    except ConfigError:
        return
    raise AssertionError("应对未知能力抛 ConfigError")
