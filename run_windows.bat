@echo off
REM ============================================================
REM  Interceptor - portable Windows launcher
REM  No Python installation required. On first run this pulls a
REM  self-contained (embeddable) Python into .\pydist, installs
REM  dependencies there, and starts Interceptor. Nothing is
REM  installed system-wide, no admin needed. Delete the folder
REM  to remove everything.
REM ============================================================
setlocal
cd /d "%~dp0"

set "PYVER=3.11.9"
set "PYDIR=%~dp0pydist"
set "PYEXE=%PYDIR%\python.exe"
set "PYZIP=%TEMP%\python-embed-%PYVER%.zip"

if exist "%PYEXE%" goto run

echo ============================================================
echo  First-time setup - fetching a portable Python (one time).
echo  Nothing is installed on your system.
echo ============================================================

REM --- download the official embeddable Python (no installer) ---
echo Downloading portable Python %PYVER% ...
powershell -NoProfile -Command ^
  "try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/%PYVER%/python-%PYVER%-embed-amd64.zip' -OutFile '%PYZIP%' -UseBasicParsing } catch { Write-Host $_; exit 1 }"
if not exist "%PYZIP%" ( echo Download failed. Check your internet connection. & pause & exit /b 1 )

echo Extracting ...
powershell -NoProfile -Command "Expand-Archive -Force -Path '%PYZIP%' -DestinationPath '%PYDIR%'"
del "%PYZIP%" >nul 2>&1

REM --- enable site-packages so pip-installed deps are importable ---
echo import site>> "%PYDIR%\python311._pth"

REM --- bootstrap pip ---
echo Installing pip ...
powershell -NoProfile -Command ^
  "try { Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%PYDIR%\get-pip.py' -UseBasicParsing } catch { Write-Host $_; exit 1 }"
"%PYEXE%" "%PYDIR%\get-pip.py" --no-warn-script-location
if errorlevel 1 ( echo pip bootstrap failed. & pause & exit /b 1 )

REM --- install project dependencies into the portable Python ---
echo Installing dependencies (mitmproxy, fastapi, uvicorn, httpx) ...
"%PYEXE%" -m pip install --no-warn-script-location -r "%~dp0requirements.txt"
if errorlevel 1 ( echo Dependency install failed. & pause & exit /b 1 )

echo.
echo Setup complete.
echo.

:run
echo ============================================================
echo  Starting Interceptor
echo    Web UI : http://127.0.0.1:8000
echo    Proxy  : 127.0.0.1:8080
echo  Leave this window open. Press Ctrl+C here to stop.
echo ============================================================
"%PYEXE%" "%~dp0run.py" %*
pause
endlocal
