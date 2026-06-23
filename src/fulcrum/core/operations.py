"""操作注册表(`@operation`)—— 面向控制台/操作员的「能力」单一真源,AI 工具表从它自动派生。

与 `core/registry.py`(`@capability`,注册**管线内部能力**喂给 SecurityPipeline)平行而互补:
本表注册**面向操作员的操作**(查、办、跳),喂给 AI 操作助手。框架硬约定见 arch/01 §5.1:

    队友新增一个控制台能力 = `@operation` 注册一次 → 助手**零改**即可调用它。

助手启动时不读任何写死的工具清单,而是 `operation_registry.visible_for(principal)`——按角色权限
过滤后把每个 operation 的 name/description/params 直接转成模型的 function-calling 工具。

纯核心:本模块只依赖标准库与 domain,**不**依赖 adapters/capabilities/框架(import-linter 强制)。
operation 的 handler 由各领域适配器模块注册进来(对称 `@capability` 的实现类住在 capabilities/),
core 不反向 import 它们;handler 的 `principal`/`services` 在 core 侧按结构化鸭子类型(Any)看待。
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .errors import ConfigError

# 操作的三类能力面(与 plan/11 §2 对齐)。新增 kind 需架构评审,不可随意扩张。
KINDS: frozenset[str] = frozenset({"ui", "read", "write"})

# 风险分级(与前端动作目录同口径):只读 / 一般 / 高危。
RISK_LEVELS: frozenset[str] = frozenset({"read_only", "normal", "high"})

# 函数名须满足 OpenAI function-calling 规范(喂给模型当工具名)。
_NAME_RE = re.compile(r"^[a-zA-Z0-9_]+$")

# handler 契约:(args, principal, services) -> OperationResult。
# principal/services 在 core 侧按鸭子类型看待(Any),实现由 adapters 注入。
OperationHandler = Callable[[dict, Any, Any], Awaitable["OperationResult"]]


@dataclass(slots=True)
class OperationResult:
    """一次 operation 执行的产物。

    summary —— **喂回模型**的简短文本(read 类把大对象压成这段,防灌爆上下文);
    data    —— 结构化结果(回前端 / 落审计),可为任意可序列化对象;
    ok/error—— 执行成败(失败也不抛,交由助手循环据此续/止)。
    """

    summary: str
    data: Any = None
    ok: bool = True
    error: str | None = None
    # 仅 write:执行时捕获的**前态快照**(撤销所需的参数),喂给 undo_handler 即回滚。
    # 例如改状态前的旧 status、改配置前的整份旧配置。None=本次无可撤销快照。
    undo: dict | None = None


@dataclass(frozen=True, slots=True)
class AssistantTool:
    """注册表条目 —— 一个可被 AI 调用的操作描述符(plan/11 §2.1)。"""

    name: str  # 给模型看的函数名(^[a-zA-Z0-9_]+$)
    kind: str  # ui | read | write
    label: str  # 给人看的中文名
    description: str  # 给模型看的用途(决定模型何时选它)
    parameters: dict = field(default_factory=dict)  # JSON Schema(OpenAI function 参数规范)
    requires: tuple[str, ...] = ()  # 所需权限点(RBAC)
    risk: str = "read_only"  # read_only | normal | high
    handler: OperationHandler | None = None  # read/write:进程内执行;ui:None(前端执行)
    reversible: bool = False  # write 是否可一键撤销
    inverse: str | None = None  # 逆操作的人读名(展示用,如 "恢复为待审批");None=不可撤销
    # write 撤销执行器:吃 handler 执行时返回的 `OperationResult.undo`(前态快照)→ 回滚。
    # reversible=True 必须提供;reversible=False(如幂等无副作用的扫描)可缺。
    undo_handler: OperationHandler | None = None

    def visible_to(self, principal: Any) -> bool:
        """该角色是否被授权调用本操作(requires ⊆ 角色权限)。"""
        return all(principal.has(p) for p in self.requires)


class OperationRegistry:
    """name -> AssistantTool。进程内单例,装配时由各领域模块 import 触发注册。"""

    def __init__(self) -> None:
        self._ops: dict[str, AssistantTool] = {}

    def register(self, tool: AssistantTool) -> AssistantTool:
        if tool.kind not in KINDS:
            raise ConfigError(f"未知操作 kind={tool.kind!r};允许:{sorted(KINDS)}")
        if not _NAME_RE.match(tool.name):
            raise ConfigError(f"操作名非法 name={tool.name!r};须匹配 ^[a-zA-Z0-9_]+$")
        if tool.risk not in RISK_LEVELS:
            raise ConfigError(f"未知 risk={tool.risk!r};允许:{sorted(RISK_LEVELS)}")
        if tool.name in self._ops:
            raise ConfigError(f"操作重复注册:name={tool.name!r}")
        # read/write 必须有进程内 handler;ui 由前端执行,不得带 handler。
        if tool.kind == "ui" and tool.handler is not None:
            raise ConfigError(f"ui 操作由前端执行,不应带 handler:name={tool.name!r}")
        if tool.kind in ("read", "write") and tool.handler is None:
            raise ConfigError(f"{tool.kind} 操作必须提供 handler:name={tool.name!r}")
        # write 若声明可撤销则必须给出撤销执行器(plan/11 §6:可撤销或显式标不可撤销)。
        if tool.kind == "write" and tool.reversible and tool.undo_handler is None:
            raise ConfigError(f"可撤销的 write 操作必须提供 undo_handler:name={tool.name!r}")
        self._ops[tool.name] = tool
        return tool

    def get(self, name: str) -> AssistantTool | None:
        return self._ops.get(name)

    def all(self) -> list[AssistantTool]:
        return list(self._ops.values())

    def names(self) -> list[str]:
        return sorted(self._ops)

    def visible_for(self, principal: Any) -> list[AssistantTool]:
        """当前角色能调的操作 = 助手能用的工具 = 模型看得到的候选(单一真源)。

        越权工具**根本不进**模型候选;执行点仍会纵深复校(deps.require / handler 内),
        前端隐藏≠安全。
        """
        return [t for t in self._ops.values() if t.visible_to(principal)]

    def clear(self) -> None:
        """仅供测试隔离用(进程内单例,测试间复位)。"""
        self._ops.clear()


# 全局注册表(进程内单例)。各领域适配器模块 import 时把自己的 operation 注册进来。
operation_registry = OperationRegistry()


def operation(
    *,
    name: str,
    kind: str,
    label: str,
    description: str,
    params: dict | None = None,
    requires: tuple[str, ...] = (),
    risk: str = "read_only",
    reversible: bool = False,
    inverse: str | None = None,
) -> Callable[[OperationHandler], OperationHandler]:
    """函数装饰器:把一个 read/write handler 注册成 AI 可调操作。

    ui 类无 handler(前端执行),直接构造 `AssistantTool` 调 `operation_registry.register`。
    """

    def deco(fn: OperationHandler) -> OperationHandler:
        operation_registry.register(
            AssistantTool(
                name=name,
                kind=kind,
                label=label,
                description=description,
                parameters=params or {"type": "object", "properties": {}},
                requires=requires,
                risk=risk,
                handler=fn,
                reversible=reversible,
                inverse=inverse,
            )
        )
        return fn

    return deco
