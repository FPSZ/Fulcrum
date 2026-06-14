"""`python -m fulcrum` —— 启动枢衡 API 服务。"""

from __future__ import annotations

from .config import Settings


def main() -> None:
    import uvicorn

    from .app import create_app

    settings = Settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
