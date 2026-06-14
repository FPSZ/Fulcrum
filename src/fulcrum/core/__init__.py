"""core —— 六边形内核:领域类型 + 抽象接口 + 注册表 + 管线编排。

铁律:本包**不得**依赖任何框架或具体实现(FastAPI / DB / httpx / capabilities / adapters)。
只允许依赖标准库与 pydantic。依赖方向由 import-linter 在 CI 强制(见 pyproject)。
"""
