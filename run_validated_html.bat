@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -c "import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)"
  if errorlevel 1 (
    echo Přísný HTML profil vyžaduje Python 3.10 nebo novější.
    pause
    exit /b 1
  )
  py -3 validated_bridge.py
) else (
  python -c "import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)"
  if errorlevel 1 (
    echo Přísný HTML profil vyžaduje Python 3.10 nebo novější.
    pause
    exit /b 1
  )
  python validated_bridge.py
)
if errorlevel 1 pause
