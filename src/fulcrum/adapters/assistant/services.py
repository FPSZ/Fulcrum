"""AssistantServices —— 操作 handler 在执行时能拿到的后端服务句柄(装配根注入)。

operation 的描述符住在 core(纯);它的 handler 住在 adapters,执行时需要真实服务(管线/目录/
扫描器/各配置存储)。装配根 `build_api` 把这些组装进本 bundle,逐次调用透传给 handler——
core 不认识这些具体类型,handler 按结构化字段取用。读类 handler 借此复用各路由背后的同一份
数据访问,与 REST 端点同源(不另起一套读法,避免漂移)。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline
    from ...core.ports import SupplyChainScanner
    from ..auth import DirectoryService
    from ..console_settings import ConsoleSettingsStore
    from ..gateway import GatewayConfigStore


@dataclass(slots=True)
class AssistantServices:
    pipeline: SecurityPipeline
    eval_report_path: str
    supply_manifest_dir: str
    directory: DirectoryService | None = None
    scanner: SupplyChainScanner | None = None
    gateway_store: GatewayConfigStore | None = None
    console_store: ConsoleSettingsStore | None = None
