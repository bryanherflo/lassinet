@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel% equ 0 (
    python run.py %*
) else (
    py -3 run.py %*
)
if errorlevel 1 pause
