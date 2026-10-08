@echo off
rem Load ~100 synthetic services into your local CATS (docker compose).
rem Reads CATS_PORT and PIPELINE_API_TOKEN from .env. Extra options pass through,
rem e.g.  load-test.bat --services 20 --max-findings 2000
cd /d "%~dp0"
set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
"%PY%" scripts\load-test-portfolio.py %*
echo.
pause
