@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -c "import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)"
  if errorlevel 1 (
    echo EntropyForge vyzaduje Python 3.10 nebo novejsi.
    pause
    exit /b 1
  )
  py -3 entropy_forge.py
) else (
  python -c "import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)"
  if errorlevel 1 (
    echo EntropyForge vyzaduje Python 3.10 nebo novejsi.
    pause
    exit /b 1
  )
  python entropy_forge.py
)
if errorlevel 1 pause
