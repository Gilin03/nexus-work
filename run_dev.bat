@echo off
chcp 65001 > nul
cd /d "%~dp0"
title NEXUS WORK - Development Server (Werkzeug)
echo [NEXUS WORK] 개발용 서버를 시작합니다 (--dev)...
call .venv\Scripts\python.exe run.py --host 0.0.0.0 --port 5070 --dev
pause
