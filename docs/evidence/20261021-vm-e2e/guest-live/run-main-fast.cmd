@echo off
set BVMENV_GUEST=1
set BLOOK_ALLOW_KERNEL_LOAD=1
cd /d C:\blook\kc-main
powershell -NoProfile -ExecutionPolicy Bypass -File guest-run.ps1 -LatencyCalls 200 -SoakCalls 5000 > guest-run.out 2>&1
echo MAIN_EXIT=%ERRORLEVEL% >> guest-run.out