"""python -m fulcrum.enterprise —— 启动企业智能体(被保护方)于 127.0.0.1:8800。"""

from __future__ import annotations

import uvicorn

from .server import app

if __name__ == "__main__":
    print("企业政务智能体(被保护方):http://127.0.0.1:8800")
    uvicorn.run(app, host="127.0.0.1", port=8800, log_level="warning")
