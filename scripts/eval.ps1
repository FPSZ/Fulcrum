# 运行枢衡评测(M0 占位;M1 接样例集与指标计算)。
# 用法:./scripts/eval.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv run python -m fulcrum.eval @args
} else {
    python -m fulcrum.eval @args
}
