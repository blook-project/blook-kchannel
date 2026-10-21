@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0guest-run.ps1"
exit /b %ERRORLEVEL%
