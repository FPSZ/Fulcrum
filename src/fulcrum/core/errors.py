"""领域错误类型 —— 集中定义,adapters 层统一映射为 HTTP/CLI 错误。"""

from __future__ import annotations


class FulcrumError(Exception):
    """枢衡领域错误基类。"""


class ConfigError(FulcrumError):
    """配置/装配错误(未知能力、重复注册、配置缺失等)。"""


class PolicyViolation(FulcrumError):
    """动作违反安全策略。"""


class SandboxDenied(FulcrumError):
    """沙箱拒绝执行(越界/超限/外联等)。"""


class AuditError(FulcrumError):
    """审计写入或校验失败。"""
