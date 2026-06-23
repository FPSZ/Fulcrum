# 一键启动枢衡 Fulcrum 业务台(默认配置)。
# 端口 8099 · 前端 console/dist · 数据 data/runtime/ · 模型走 .env(MiMo 密钥仅在 .env)。
# 登录:admin / Fulcrum@2026(首启空库时按此引导;已建库则沿用库内口令)。
#
# 用法:右键「用 PowerShell 运行」 scripts/demo.ps1,或双击根目录 启动.cmd。
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# ── 运行参数(环境变量优先于 .env;模型/密钥不在这里,继续由 .env 注入)──
$env:FULCRUM_HOST = "127.0.0.1"
$env:FULCRUM_PORT = "8099"
$env:FULCRUM_FRONTEND_DIR = "console/dist"
# 仅在数据库为空时生效;已存在的 admin 不会被改写。
$env:FULCRUM_BOOTSTRAP_ADMIN_PASSWORD = "Fulcrum@2026"

if (-not (Test-Path "console/dist/index.html")) {
    Write-Warning "未找到 console/dist 前端构建,先构建:在 console/ 下执行 npm run build"
}
if (-not (Test-Path ".env")) {
    Write-Warning "缺少 .env(MiMo 模型端点/密钥),操作助手将不可用。参考 .env.example。"
}

Write-Host ""
Write-Host "  枢衡 Fulcrum 业务台启动中……" -ForegroundColor Cyan
Write-Host "  地址:http://127.0.0.1:8099" -ForegroundColor Green
Write-Host "  账号:admin   口令:Fulcrum@2026" -ForegroundColor Green
Write-Host "  停止:Ctrl + C" -ForegroundColor DarkGray
Write-Host ""

if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv run python -m fulcrum
} else {
    python -m fulcrum
}
