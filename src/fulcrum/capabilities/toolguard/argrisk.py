"""工具参数风险判定 —— risk_scorer 与 policy 共用的确定性纯函数。

约定的参数形态(与内置 4 工具对齐,见路线图 P0-b):
    file.read / file.write : {"path": "..."}
    http.request           : {"url": "...", "method": "GET", "body": "..."}
    shell.exec             : {"command": "..."}

纯函数、无副作用、可解释:同一份判断同时服务"风险评分"与"策略匹配",避免两处口径漂移。
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# 敏感文件/路径:系统账户、密钥、凭据、env、证书。
_SENSITIVE_PATH = re.compile(
    r"(/etc/(passwd|shadow)|id_rsa|\.ssh|\.env\b|\.pem\b|\.key\b|secret|credential|password|"
    r"密钥|私钥|口令|凭据|凭证|涉密)",
    re.IGNORECASE,
)
# 危险 shell 片段:删除、外联下载、反弹 shell、提权、磁盘操作。
_DANGEROUS_CMD = re.compile(
    r"(rm\s+-rf|\b(curl|wget)\b|\bnc\b\s+-e|base64\s+-d|chmod\s+777|/bin/sh|bash\s+-c|"
    r"powershell|mkfs|dd\s+if=|shutdown|reboot|:\(\)\s*\{)",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_WIN_DRIVE = re.compile(r"^[A-Za-z]:")


def _arg_path(arguments: dict) -> str:
    return str(arguments.get("path") or arguments.get("file") or "")


def path_sensitive(arguments: dict) -> bool:
    return bool(_SENSITIVE_PATH.search(_arg_path(arguments)))


def path_outside_workspace(arguments: dict, workspace: str) -> bool:
    """上级穿越、或不在 workspace 前缀内的绝对/盘符路径 → 越界。"""
    raw = _arg_path(arguments)
    if not raw:
        return False
    norm = raw.replace("\\", "/")
    if ".." in norm:
        return True
    ws = workspace.replace("\\", "/").rstrip("/")
    if norm == ws or norm.startswith(ws + "/"):
        return False
    return norm.startswith("/") or bool(_WIN_DRIVE.match(norm))


def command_dangerous(arguments: dict) -> bool:
    cmd = str(arguments.get("command") or arguments.get("cmd") or "")
    return bool(_DANGEROUS_CMD.search(cmd))


def url_host(arguments: dict) -> str | None:
    url = str(arguments.get("url") or "")
    if not url:
        return None
    host = urlparse(url if "://" in url else f"//{url}").hostname
    return host.lower() if host else None


def domain_allowed(arguments: dict, allow_domains: list[str]) -> bool:
    """无 URL → 不涉及白名单,返回 True;有 URL → 命中白名单(含子域)才放行。"""
    host = url_host(arguments)
    if host is None:
        return True
    return any(host == d.lower() or host.endswith("." + d.lower()) for d in allow_domains)


def is_raw_ip(arguments: dict) -> bool:
    host = url_host(arguments)
    return bool(host and _IPV4.match(host))
