@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0app\Start.ps1" -Mode Web
if errorlevel 1 pause
