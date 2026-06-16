"""领域错误类型 —— 集中定义,adapters 层统一映射为 HTTP/CLI 错误。

设计哲学:**安全结论是数据,不是异常**。策略处置走 `PolicyDecision`、执行结果走 `ExecResult`,
管线逐级 fail-closed 返回 BLOCK/错误结果,绝不靠抛异常表达"被拦截/被拒绝"。异常只保留给
**真正的故障**:配置/装配错误、审计链损坏等。因此这里只有两类具体错误。
"""

from __future__ import annotations


class FulcrumError(Exception):
    """枢衡领域错误基类。"""


class ConfigError(FulcrumError):
    """配置/装配错误(未知能力、重复注册、配置缺失、策略文件缺失等)。"""


class AuditError(FulcrumError):
    """审计写入或校验故障(如未知 schema_version 无法核验哈希链)。"""
