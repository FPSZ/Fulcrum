# 运行枢衡评测(M0 占位;M1 接样例集与指标计算)。
# 用法:./scripts/eval.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv run python -m fulcrum.eval @args
} else {
    python -m fulcrum.eval @args
}
