"""API 层 DTO(请求/响应 schema)。FastAPI 据此自动产出 OpenAPI。

按职责域拆分(chat / gateway / monitoring / admin / assistant),本包**重导出全部** ——
调用方仍 `from ..api.schemas import X` 一处取用,拆分对外零感知。新增 DTO 放对应域文件 +
其 `__all__` 即自动可见。
"""

from __future__ import annotations

from .admin import *  # noqa: F403
from .admin import __all__ as _admin_all
from .assistant import *  # noqa: F403
from .assistant import __all__ as _assistant_all
from .chat import *  # noqa: F403
from .chat import __all__ as _chat_all
from .gateway import *  # noqa: F403
from .gateway import __all__ as _gateway_all
from .monitoring import *  # noqa: F403
from .monitoring import __all__ as _monitoring_all

__all__ = [
    *_chat_all,
    *_gateway_all,
    *_monitoring_all,
    *_admin_all,
    *_assistant_all,
]
