@echo off
color 0B
echo ===================================================
echo       NETMON - GITHUB OTOMATIK YUKLEME ARACI
echo ===================================================
echo.
echo Kodlar GitHub deponuza (AtakaanShiva) gonderiliyor...
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0auto-push.ps1"

echo.
echo ===================================================
echo Islem tamamlandi! Kapatmak icin bir tusa basin.
pause >nul
