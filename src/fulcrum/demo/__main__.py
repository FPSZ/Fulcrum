"""`python -m fulcrum.demo` 入口。"""

from __future__ import annotations

import asyncio

from . import main

if __name__ == "__main__":
    asyncio.run(main())
