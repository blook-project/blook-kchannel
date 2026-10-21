@echo off
set BVMENV_GUEST=1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0guest-run.ps1"
exit /b %ERRORLEVEL%
