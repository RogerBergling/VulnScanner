@echo off
setlocal
cd /d "%~dp0"

rem Load simple KEY=VALUE pairs from .env (comments and blank lines ignored).
if exist .env (
  for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    echo %%A | findstr /b /c:"#" >nul || set "%%A=%%B"
  )
)

if not exist .venv\Scripts\python.exe (
  echo [vulnscanner] Creating .venv
  py -3 -m venv .venv 2>nul || python -m venv .venv
  if errorlevel 1 goto :error
)

if not exist .venv\.deps-ok (
  echo [vulnscanner] Installing Python dependencies
  .venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
  if errorlevel 1 goto :error
  type nul > .venv\.deps-ok
)

if not defined VS_HOST set "VS_HOST=127.0.0.1"
if not defined VS_PORT set "VS_PORT=8765"
if not defined VS_SSL set "VS_SSL=true"

set "SCHEME=http"
if /I "%VS_SSL%"=="1" set "SCHEME=https"
if /I "%VS_SSL%"=="true" set "SCHEME=https"
if /I "%VS_SSL%"=="yes" set "SCHEME=https"
if /I "%VS_SSL%"=="on" set "SCHEME=https"

echo [vulnscanner] Starting on %SCHEME%://%VS_HOST%:%VS_PORT%
.venv\Scripts\python.exe -m app.main
exit /b %errorlevel%

:error
echo [vulnscanner] Startup failed. See the message above.
exit /b 1
