"""能力注册表(插件式扩展点)。

队友"加功能"的唯一标准姿势:
    1. 在 capabilities/ 下实现某个 port 接口;
    2. 用 @capability("<kind>", "<name>") 装饰注册;
    3. 在 config/fulcrum.yml 里按 name 启用。
核心管线零改动。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from .errors import ConfigError

# 固定的能力类型;新增 kind 需经架构评审,不可随意扩张。
KINDS: frozenset[str] = frozenset(
    {
        "labeler",
        "detector",
        "attributor",
        "risk_scorer",
        "chain_analyzer",
        "policy",
        "tool",
        "executor",
        "scanner",
        "model",
        "audit",
    }
)

_T = TypeVar("_T")


class Registry:
    """kind -> { name -> factory }。factory 通常就是实现类本身。"""

    def __init__(self) -> None:
        self._factories: dict[str, dict[str, Callable[..., Any]]] = {}

    def register(self, kind: str, name: str, factory: Callable[..., Any]) -> None:
        if kind not in KINDS:
            raise ConfigError(f"未知能力类型 kind={kind!r};允许:{sorted(KINDS)}")
        bucket = self._factories.setdefault(kind, {})
        if name in bucket:
            raise ConfigError(f"能力重复注册:kind={kind!r} name={name!r}")
        bucket[name] = factory

    def create(self, kind: str, name: str, /, **kwargs: Any) -> Any:
        try:
            factory = self._factories[kind][name]
        except KeyError as exc:
            raise ConfigError(
                f"未找到能力实现:kind={kind!r} name={name!r};已注册:{self.names(kind)}"
            ) from exc
        return factory(**kwargs)

    def names(self, kind: str) -> list[str]:
        return sorted(self._factories.get(kind, {}))


# 全局注册表(进程内单例)。
registry = Registry()


def capability(kind: str, name: str) -> Callable[[type[_T]], type[_T]]:
    """类装饰器:把实现类注册进全局注册表。"""

    def deco(cls: type[_T]) -> type[_T]:
        registry.register(kind, name, cls)
        return cls

    return deco
