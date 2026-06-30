@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist ".venv\Lib\site-packages\yinhu.pth" del /q ".venv\Lib\site-packages\yinhu.pth"
set "PYTHONPATH=%~dp0src"
set "PYTHONUTF8=1"
".venv\Scripts\python.exe" -m yinhu
pause
