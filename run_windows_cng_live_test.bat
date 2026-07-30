@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 tests\windows_cng_live_test.py
) else (
  python tests\windows_cng_live_test.py
)
set "entropyforge_status=%errorlevel%"
echo.
pause
exit /b %entropyforge_status%
