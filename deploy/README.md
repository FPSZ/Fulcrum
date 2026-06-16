# deploy · 单容器部署

一个镜像同时提供**控制台前端 + 安全网关/管控 API**(同一进程、同一端口),私有化单机部署。
方案背景与边界见 [docs/plan/04-单容器部署方案.md](../docs/plan/04-单容器部署方案.md)。

## 一条命令起服务(推荐)

在**仓库根目录**执行:

```bash
cp .env.example .env        # 首次:按需改模型端点/密钥等(.env 不入库)
docker compose -f deploy/docker-compose.yml up -d --build
```

浏览器打开 <http://localhost:8000> 即为控制台,API 同端口。首次启动会在日志打印一次性管理员口令
(若 `FULCRUM_BOOTSTRAP_ADMIN_PASSWORD` 留空):`docker compose -f deploy/docker-compose.yml logs | grep 管理员`。

停止 / 重启 / 看日志:

```bash
docker compose -f deploy/docker-compose.yml down        # 停止(数据卷保留)
docker compose -f deploy/docker-compose.yml up -d       # 再次启动(不重建)
docker compose -f deploy/docker-compose.yml logs -f     # 跟踪日志
```

## 不用 compose 的等价 docker 命令

```bash
docker build -t fulcrum:latest -f deploy/Dockerfile .
docker run -d --name fulcrum -p 8000:8000 \
  --env-file ./.env \
  -e FULCRUM_HOST=0.0.0.0 \
  -v fulcrum-data:/app/data/runtime \
  fulcrum:latest
```

> ⚠️ 裸 `docker run` 用 `--env-file` 时,务必显式 `-e FULCRUM_HOST=0.0.0.0`(否则 `.env` 里的
> `127.0.0.1` 会让容器只在内部监听、宿主访问不到)。compose 已替你设好,无此坑。

## 起了哪些服务 / 没起哪些

- ✅ **生产服务**(本镜像内,单进程):控制台前端(静态托管)+ 安全网关 `/gateway/*` + 管控/审计/鉴权 API。
- ❌ **测试靶机不在镜像内**:被保护方企业智能体(`python -m fulcrum.enterprise`,:8800)、政务沙盘 demo
  ——它们模拟"客户侧被保护智能体",仅供本地联调/演示;生产部署由**客户自己的智能体**充当网关上游。

## 数据与密钥

- **密钥/配置只走 `.env`**(模型端点/密钥、会话、引导管理员等),绝不写进镜像、不入前端、不入库;镜像内只留 `.env.example`。
- **运行数据挂卷** `fulcrum-data → /app/data/runtime`:SQLite 审计库 / 鉴权库、网关上游接入配置(`gateway.json`)等,容器重建不丢。
- 跨平台:同一 Linux 镜像在 Linux / Windows / macOS(Docker Desktop)行为一致。

## 约定

- 不提交真实 `.env`、证书、密钥或私有部署凭据。
- 临时部署日志与运行产物不进入本目录。
