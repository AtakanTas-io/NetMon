@echo off
setlocal
cd /d "%~dp0\..\.."

where python >nul 2>nul
if errorlevel 1 (
    echo HATA: Python bulunamadi.
    pause
    exit /b 1
)

set "NETMON_USER_DATA=%USERPROFILE%\.netmon"
python backend\admin_recovery.py --database "%NETMON_USER_DATA%\netmon.db" --output "%NETMON_USER_DATA%\initial_admin_password.txt"
if errorlevel 1 (
    pause
    exit /b 1
)

echo.
echo Parola dosyasi Not Defteri ile aciliyor.
start "" notepad "%NETMON_USER_DATA%\initial_admin_password.txt"
pause
