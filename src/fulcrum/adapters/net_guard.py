"""出站端点校验 —— 给"运行时可配的服务端会去请求的 URL"加 SSRF 闸。

威胁:操作助手模型接入 / 网关上游的 endpoint 由管理员在控制台填,服务端据此发起请求。
若不校验,可被指向 `file://`、`http://169.254.169.254`(云元数据)等,把本机变 SSRF 跳板。

取舍(本产品是**本地私有化**部署,模型常驻 localhost / 内网):
- **放行** loopback(127.0.0.1/::1)与私网(10/172.16/192.168)—— 本地 Ollama/vLLM/llama.cpp
  就在这些地址,封了等于废掉核心功能。
- **拦截** 非 http(s) 协议、链路本地 169.254.0.0/16(含云元数据 169.254.169.254)、组播/保留段、
  以及 `metadata` / `metadata.google.internal` 等元数据主机名。
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_METADATA_HOSTS = {"metadata", "metadata.google.internal"}


def validate_endpoint(endpoint: str) -> str:
    """校验出站端点;非法抛 ValueError(由 pydantic 转 422 / 保存失败)。空串视为未配置,放行。"""
    e = (endpoint or "").strip()
    if not e:
        return endpoint
    parsed = urlparse(e)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("端点必须以 http:// 或 https:// 开头(禁止 file/gopher 等协议)")
    host = (parsed.hostname or "").strip()
    if not host:
        raise ValueError("端点缺少主机名")
    if host.lower() in _METADATA_HOSTS:
        raise ValueError("端点不得指向云元数据服务")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_link_local or ip.is_multicast or ip.is_reserved):
        # 链路本地含 169.254.169.254 云元数据。loopback/私网按本地私有化需要放行。
        raise ValueError("端点不得指向链路本地 / 元数据 / 保留地址")
    return endpoint
