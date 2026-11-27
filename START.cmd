@echo off
cd /d "%~dp0"
if not exist node_modules call npm.cmd install
call npm.cmd run build
if errorlevel 1 (
 pause
 exit /b 1
)
start "" http://127.0.0.1:8787
node server.mjs
pause
