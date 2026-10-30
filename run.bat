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

rem uv-created environments may not include pip; the launcher uses pip for the
rem hashed lock install.
.venv\Scripts\python.exe -m pip --version >nul 2>&1
if errorlevel 1 (
  echo [vulnscanner] Bootstrapping pip
  .venv\Scripts\python.exe -m ensurepip --upgrade
  if errorlevel 1 goto :error
)

rem Install the hashed lock file. pip is idempotent when the packages are
rem already satisfied, and hash verification rejects modified artifacts.
echo [vulnscanner] Checking locked Python dependencies
.venv\Scripts\python.exe -m pip install --disable-pip-version-check --require-hashes -r requirements.txt
if errorlevel 1 goto :error

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
