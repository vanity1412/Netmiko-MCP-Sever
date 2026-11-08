@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0app\Start.ps1" -Mode Terminal
if errorlevel 1 pause
