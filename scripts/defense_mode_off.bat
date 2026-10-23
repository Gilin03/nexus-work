@echo off
chcp 65001 >nul
cd /d "%~dp0.."
.venv\Scripts\python.exe scripts\toggle_defense.py off
echo.
pause
