@echo off
chcp 65001 > nul
cd /d "%~dp0"
title NEXUS WORK - Production WSGI Server (Waitress)
echo [NEXUS WORK] 프로덕션 WSGI 서버를 시작합니다...
call .venv\Scripts\python.exe run.py --host 0.0.0.0 --port 5070
pause
