# 启动枢衡 API 服务(本地开发)。
# 用法:./scripts/run.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv run python -m fulcrum
} else {
    python -m fulcrum
}
