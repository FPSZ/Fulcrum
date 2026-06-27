# 枢衡 Fulcrum · 单容器镜像(多阶段构建)
# 一个镜像同时提供「控制台前端 + 安全网关/管控 API」;前端静态资源由后端直接托管。
# 不含被保护方企业智能体 / 政务沙盘 demo 等**测试用上游服务**(那是靶机,不进生产镜像)。
#
# 构建:  docker build -t fulcrum:latest -f deploy/Dockerfile .
# 运行:  见 deploy/README.md(推荐 deploy/docker-compose.yml 一条命令起)

# ── Stage 1:前端构建(Node 仅构建期出现,不进运行镜像)──────────────────
FROM node:20-slim AS frontend
WORKDIR /console

# 先装依赖(利用层缓存):仅复制清单 + 镜像源配置,命中缓存时跳过重装
COPY console/package.json console/package-lock.json console/.npmrc ./
RUN npm ci

# 再复制源码构建 → /console/dist(Vite 默认产物目录)
COPY console/ ./
RUN npm run build

# ── Stage 2:Python 运行时(锁定 3.11,与 requires-python 对齐)──────────────
FROM python:3.11-slim AS runtime
WORKDIR /app

# uv:按 uv.lock 复现锁定依赖,保证可重复构建
RUN pip install --no-cache-dir uv

# 依赖与本包安装(先放清单 + 源码,hatchling 需要源码才能构建本包 wheel)
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv sync --frozen --no-dev

# 只读运行资产:策略文件 / 工具工作区等(data/runtime 由 .dockerignore 排除,运行期挂卷)
COPY data/ ./data/
COPY .env.example ./.env.example

# 从前端构建阶段拷入静态产物 → 后端托管目录
COPY --from=frontend /console/dist ./console/dist

# 以非 root 运行:容器内若被 RCE/逃逸,不直接拿到 root;与配置文件 0600 + 审计库构成纵深。
# 预建运行目录并归属该用户,使挂载的命名卷(data/runtime)初始即可写(Docker 继承挂载点属主)。
RUN mkdir -p /app/data/runtime \
    && useradd --system --uid 10001 --shell /usr/sbin/nologin fulcrum \
    && chown -R fulcrum:fulcrum /app
USER fulcrum

# 容器内默认值:对外可达(0.0.0.0)+ 指向已构建的前端静态目录。
# 注:用 --env-file 注入的同名变量会覆盖此处;compose 已显式重申 0.0.0.0。
ENV PATH="/app/.venv/bin:$PATH" \
    FULCRUM_HOST=0.0.0.0 \
    FULCRUM_PORT=8000 \
    FULCRUM_FRONTEND_DIR=/app/console/dist

EXPOSE 8000

# 单进程即全部服务端逻辑(API + 网关 + 控制台静态托管)
CMD ["python", "-m", "fulcrum"]
