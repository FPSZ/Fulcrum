"""供应链组件登记落盘 —— 控制台「登记组件」上传的 manifest 持久化到运行时目录。

每个组件存一个 manifest 文件(.yml,内容即用户提交的原文)。文件名据 component_id 净化得到,
同一组件再次登记即覆盖(去重以最新为准)。与仓库种子目录(samples/supplychain)分离:种子是
随仓库发布的演示样本,本目录是运行期录入数据(data/runtime,已 gitignore;Docker 挂卷即持久)。

低频写,文件足够;原子替换避免半截写入。供应链页列表 = 种子目录 + 本目录合并扫描(见 supply_routes)。
"""

from __future__ import annotations

import contextlib
import os
import re
import tempfile
from pathlib import Path

# 文件名只保留这些字符,其余替换为 _,避免 component_id 里的 / 、空格、@ 造成越权写或非法路径。
_SAFE = re.compile(r"[^A-Za-z0-9._@-]+")


def _safe_name(component_id: str) -> str:
    """component_id → 安全文件名(无后缀)。空/全非法字符兜底 component。"""
    name = _SAFE.sub("_", component_id)
    name = re.sub(r"\.{2,}", ".", name).strip("._") or "component"  # 收敛 .. 杜绝路径穿越形态
    return name[:120]  # 防超长文件名


class SupplyManifestStore:
    """运行时登记的组件 manifest 目录存储。每组件一个 .yml,内容为提交原文。"""

    def __init__(self, upload_dir: str) -> None:
        self._dir = Path(upload_dir)

    @property
    def dir(self) -> str:
        return str(self._dir)

    def save(self, component_id: str, manifest_text: str) -> str:
        """把 manifest 原文落为 <safe(component_id)>.yml,返回路径。同组件覆盖。"""
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{_safe_name(component_id)}.yml"
        # 原子替换:先写临时文件再 os.replace,避免半截写入被并发扫描读到。
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(manifest_text)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)  # 清理临时文件失败不掩盖原异常
            raise
        return str(path)
