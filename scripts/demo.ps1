# 一键启动枢衡 Fulcrum 业务台(自动检测 + 补齐依赖)。
# 端口 8099 · 前端 console/dist · 数据 data/runtime/ · 模型走 .env(MiMo 密钥仅在 .env)。
# 登录:admin / Fulcrum@2026(首启空库时按此引导;已建库则沿用库内口令)。
#
# 用法:双击根目录 启动.cmd,或右键「用 PowerShell 运行」本脚本。
# 自动做的事:① 没 uv 就联网装 uv(它顺带备好 Python 3.11) ② uv sync 补后端依赖
#            ③ 前端 console/dist 缺失则 npm 构建 ④ 缺 .env 给出提示 ⑤ 启动服务。
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
Set-Location (Join-Path $PSScriptRoot "..")

# ── 运行参数(环境变量优先于 .env;模型/密钥不在这里,继续由 .env 注入)──
$env:FULCRUM_HOST = "127.0.0.1"
$env:FULCRUM_PORT = "8099"
$env:FULCRUM_FRONTEND_DIR = "console/dist"
$env:FULCRUM_BOOTSTRAP_ADMIN_PASSWORD = "Fulcrum@2026"   # 仅空库时生效,不改写已存在的 admin

# ── 依赖源加速(国内干净机的最后一公里)──
# uv 默认从 pypi.org 拉依赖、从 GitHub 下 Python 3.11 运行时,国内干净机极易卡死或超时。
# 这里给出国内镜像默认值,但**仅在用户未自行配置时**才设(尊重已有 UV_* / 公司内网源),
# 且可整体跳过:设 FULCRUM_NO_MIRROR=1(如境外机器或镜像故障)即用官方源。
if (-not $env:FULCRUM_NO_MIRROR) {
    if (-not $env:UV_DEFAULT_INDEX -and -not $env:UV_INDEX_URL) {
        $env:UV_DEFAULT_INDEX = "https://pypi.tuna.tsinghua.edu.cn/simple"
    }
    if (-not $env:UV_PYTHON_INSTALL_MIRROR) {
        # python-build-standalone 的国内镜像(替换 GitHub releases 前缀)。
        $env:UV_PYTHON_INSTALL_MIRROR = "https://mirror.nju.edu.cn/github-release/astral-sh/python-build-standalone/releases/download"
    }
}

function Have($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function Step($m) { Write-Host "  > $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Die($m) {
    Write-Host ""
    Write-Host "  [X] $m" -ForegroundColor Red
    Write-Host ""
    Read-Host "  按回车退出"
    exit 1
}

Write-Host ""
Write-Host "  枢衡 Fulcrum 业务台 · 一键启动" -ForegroundColor Cyan
Write-Host "  ----------------------------------------" -ForegroundColor DarkGray

# ── 1. Python 运行器:优先 uv(顺带管 Python 3.11);没有就联网自动安装 ──
if (-not (Have uv)) {
    Warn "未检测到 uv,正在联网自动安装(uv 会顺带备好 Python 3.11)……"
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    } catch {
        Die "uv 自动安装失败(可能无网络)。请手动安装 uv:https://docs.astral.sh/uv/  或安装 Python 3.11 后重试。"
    }
    foreach ($p in @("$env:USERPROFILE\.local\bin", "$env:USERPROFILE\.cargo\bin")) {
        if (Test-Path (Join-Path $p "uv.exe")) { $env:PATH = "$p;$env:PATH" }
    }
    if (-not (Have uv)) {
        Die "uv 已安装但当前窗口未识别。请关掉本窗口、重新双击 启动.cmd 即可。"
    }
    Ok "uv 安装完成"
} else {
    Ok "检测到 uv"
}

# ── 2. 后端依赖:uv sync 补齐(首次需联网下载,含 Python 3.11 与全部三方库)──
Step "检查并补齐后端依赖(首次稍慢)……"
uv sync
if ($LASTEXITCODE -ne 0) { Die "uv sync 失败,请检查网络后重试。" }
Ok "后端依赖就绪"

# ── 3. 前端构建产物:console/dist 缺失则用 npm 构建(发包已带 dist 时直接跳过)──
if (Test-Path "console/dist/index.html") {
    Ok "前端构建产物已就绪"
} else {
    Warn "未找到前端构建产物 console/dist,尝试本地构建……"
    if (-not (Have npm)) {
        Die "前端未构建且本机没有 Node/npm。二选一:① 安装 Node.js LTS(https://nodejs.org/)后重试;② 让发包方把已构建的 console/dist 一起打包进来。"
    }
    Push-Location console
    try {
        if (-not (Test-Path "node_modules")) {
            Step "安装前端依赖 npm install(首次稍慢)……"
            npm install
            if ($LASTEXITCODE -ne 0) { Pop-Location; Die "npm install 失败,请检查网络。" }
        }
        Step "构建前端 npm run build……"
        npm run build
        if ($LASTEXITCODE -ne 0) { Pop-Location; Die "前端构建失败,请检查 Node 环境与网络。" }
    } finally {
        if ((Get-Location).Path -like "*\console") { Pop-Location }
    }
    if (-not (Test-Path "console/dist/index.html")) { Die "前端构建未产出 dist,请检查 console 工程。" }
    Ok "前端构建完成"
}

# ── 4. .env(含模型端点/密钥,无法自动生成)──
if (Test-Path ".env") {
    Ok ".env 已就绪"
} else {
    Warn ".env 缺失 → AI 操作助手不可用;网关与控制台演示不受影响。可照 .env.example 自建。"
}

# ── 5. 启动 ──
Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  启动中…… 浏览器打开:http://127.0.0.1:8099" -ForegroundColor Green
Write-Host "  账号:admin    口令:Fulcrum@2026" -ForegroundColor Green
Write-Host "  停止:在本窗口按 Ctrl + C" -ForegroundColor DarkGray
Write-Host ""
uv run python -m fulcrum
