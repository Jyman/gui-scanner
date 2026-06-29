@echo off
chcp 65001 >nul 2>&1
set "PYTHONPATH=%~dp0src"
set "PYTHONUTF8=1"
"%~dp0.venv\Scripts\python.exe" -m yinhu %*
pause
