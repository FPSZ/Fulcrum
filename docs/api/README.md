# 枢衡 API 契约(OpenAPI)

> 本文回答什么问题：后端 API 契约如何生成、校验和供前端复用，避免路由与客户端定义漂移。
> 状态：持续维护；生成结果以同目录 `openapi.json` 和当前代码为准，功能落地进度见 [`../plan/03-进度看板.md`](../plan/03-进度看板.md)。

`openapi.json` 是后端 API 的**单一契约真源**,由 FastAPI 据路由 + pydantic schema 自动产出。
前端据此生成 API client(TanStack Query 等),避免两边手抄接口导致漂移。

## 重新生成

后端路由/DTO 有改动后,重跑导出并提交更新后的 `openapi.json`:

```bash
uv run python -m fulcrum.openapi            # 写入 docs/api/openapi.json
uv run python -m fulcrum.openapi --out 其它路径.json
```

导出构建完整 app(含鉴权/管理/网关路由),鉴权/网关/审计库指向临时目录、用完即弃,
不在 `data/runtime` 留任何副本。

## 覆盖范围

核心安全(`/v1/chat/completions`、`/tools/call`、`/audit/{session_id}`)、前置网关
(`/gateway/chat`、`/admin/gateway-config`)、登录鉴权(`/auth/*`)、管理后台(`/admin/*`)、
健康检查(`/healthz`)。
