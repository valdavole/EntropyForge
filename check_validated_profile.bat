@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 validated_bridge.py --status-only
) else (
  python validated_bridge.py --status-only
)
set "entropyforge_status=%errorlevel%"
echo.
pause
exit /b %entropyforge_status%
