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
import socket
from urllib.parse import urlparse

_METADATA_HOSTS = {"metadata", "metadata.google.internal"}


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """链路本地(含 169.254.169.254 云元数据)/ 组播 / 保留 → 拦。loopback/私网按本地私有化放行。

    loopback 需显式豁免:IPv6 `::1` 在 Python 里 `is_reserved=True`,不豁免会误伤本地模型
    (`http://localhost` / `http://[::1]`),而本地私有化恰恰要放行 loopback。169.254 是链路本地
    (非 loopback),仍被拦。"""
    if ip.is_loopback:
        return False
    return ip.is_link_local or ip.is_multicast or ip.is_reserved


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
    if ip is not None:
        if _is_blocked_ip(ip):
            raise ValueError("端点不得指向链路本地 / 元数据 / 保留地址")
        return endpoint
    # 主机名:解析到 IP 再判定 —— 否则指向"解析到 169.254.169.254 的自定义域名"可绕过元数据闸
    # (只查 IP 字面量 + 两个固定元数据名并不够)。解析失败不硬拒:本地私有化部署可能填暂不可达的
    # 内网名,硬拒会误伤;残留的 DNS 重绑定面由连接侧/出口白名单兜。
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return endpoint
    for info in infos:
        try:
            resolved = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _is_blocked_ip(resolved):
            raise ValueError("端点主机名解析到链路本地 / 元数据 / 保留地址,拒绝")
    return endpoint
