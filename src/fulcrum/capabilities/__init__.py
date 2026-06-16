"""capabilities —— ports 的具体实现。队友在这里长功能。

注册采用**显式加载**(无 import 副作用):调用 load_builtin_capabilities()
触发所有内置实现向注册表注册。新增能力子模块后,在该函数内补一行 import。
"""

from __future__ import annotations


def load_builtin_capabilities() -> None:
    """显式导入所有内置能力实现,触发其 @capability 注册(幂等,可重复调用)。"""
    from .attribution import evidence, zero  # noqa: F401
    from .detectors import keyword_rules, noop  # noqa: F401
    from .labelers import passthrough, role_trust  # noqa: F401
    from .policy import allow_all, yaml_policy  # noqa: F401
    from .sandbox import echo_executor, restricted_executor  # noqa: F401
    from .supplychain import manifest_scanner  # noqa: F401
    from .supplychain import noop as supplychain_noop  # noqa: F401
    from .toolguard import heuristic, noop_chain, sequence_chain, zero_scorer  # noqa: F401
    from .tools import echo_tool, file_tools  # noqa: F401


__all__ = ["load_builtin_capabilities"]
