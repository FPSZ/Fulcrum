"""受控文件工具 file.read / file.write —— 读写限定在 demo 工作区内。

策略已在执行前拦截敏感/越界路径;工具内再做一次工作区边界校验(纵深防御),
确保即便策略被误配也不会读写工作区之外。
"""

from __future__ import annotations

from pathlib import Path

from ...core.domain import Context, ExecResult
from ...core.registry import capability

_WORKSPACE = Path("data/workspace")
_MAX_READ = 4000  # 回显截断,避免超大文件灌爆上下文
_MAX_WRITE = 1_000_000  # 单次写入字符上限(防被诱导批量落盘:磁盘耗尽 / 把外泄数据暂存进工作区)


def _resolve(raw: str) -> Path | None:
    """把工具参数路径解析到工作区内的真实路径;越界返回 None。

    兼容三种写法:工作区相对(notice.txt)、仓库相对(data/workspace/notice.txt)、绝对路径。
    """
    if not raw:
        return None
    base = _WORKSPACE.resolve()
    cand = Path(raw)
    candidates = (
        [cand.resolve()]
        if cand.is_absolute()
        else [(Path.cwd() / cand).resolve(), (base / cand).resolve()]
    )
    for target in candidates:
        if target == base or base in target.parents:
            return target
    return None


@capability("tool", "file.read")
class FileReadTool:
    name = "file.read"
    base_risk = 0.25  # 读取本身风险中低,真正的危险度由路径敏感/越界参数抬升
    model_schema = {
        "type": "function",
        "function": {
            "name": "file_read",
            "description": "读取受控工作区内的文本文件并返回内容",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "文件路径"}},
                "required": ["path"],
            },
        },
    }

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        raw = str(arguments.get("path", ""))
        target = _resolve(raw)
        if target is None:
            return ExecResult(ok=False, error=f"路径越出受控工作区,拒绝读取:{raw}")
        if not target.exists() or not target.is_file():
            return ExecResult(ok=False, error=f"文件不存在:{raw}")
        try:
            text = target.read_text(encoding="utf-8")
        except OSError as exc:
            return ExecResult(ok=False, error=f"读取失败:{exc}")
        return ExecResult(
            ok=True,
            output=text[:_MAX_READ],
            side_effects={"read_path": str(target), "bytes": len(text)},
        )


@capability("tool", "file.write")
class FileWriteTool:
    name = "file.write"
    base_risk = 0.45  # 写入有副作用,基础风险高于读取
    model_schema = {
        "type": "function",
        "function": {
            "name": "file_write",
            "description": "向受控工作区写入文本文件",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    }

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        raw = str(arguments.get("path", ""))
        content = str(arguments.get("content", ""))
        target = _resolve(raw)
        if target is None:
            return ExecResult(ok=False, error=f"路径越出受控工作区,拒绝写入:{raw}")
        if len(content) > _MAX_WRITE:
            return ExecResult(
                ok=False,
                error=f"写入内容超出上限({_MAX_WRITE} 字符),拒绝写入(防批量落盘外泄)",
            )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        except OSError as exc:
            return ExecResult(ok=False, error=f"写入失败:{exc}")
        return ExecResult(
            ok=True,
            output=f"已写入 {len(content)} 字符",
            side_effects={"write_path": str(target)},
        )
