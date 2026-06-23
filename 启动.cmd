@echo off
chcp 65001 >nul
rem 双击启动枢衡 Fulcrum 业务台(8099)。实际逻辑在 scripts\demo.ps1。
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\demo.ps1"
pause
