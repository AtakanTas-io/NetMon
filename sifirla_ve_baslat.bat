@echo off
setlocal
cd /d "%~dp0"
color 0E
echo ==============================================================
echo NETMON VERITABANI YEDEKLEME VE SIFIRLAMA ARACI
echo ==============================================================
echo.
echo Bu islem mevcut veritabanini SILMEZ; tarih damgali bir yedege tasir.
echo NetMon aciksa once uygulama penceresini kapatin.
echo.
choice /C EH /M "Devam etmek icin E, vazgecmek icin H"
if errorlevel 2 exit /b 0

taskkill /F /IM NetMon.exe /T >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$dir = Join-Path (Get-Location) 'backend';" ^
  "$db = Join-Path $dir 'netmon.db';" ^
  "if (Test-Path -LiteralPath $db) {" ^
  "  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss';" ^
  "  $backup = Join-Path $dir ('netmon_backup_' + $stamp + '.db');" ^
  "  Copy-Item -LiteralPath $db -Destination $backup -ErrorAction Stop;" ^
  "  Remove-Item -LiteralPath $db -ErrorAction Stop;" ^
  "  foreach ($suffix in @('-wal','-shm','-journal')) { $side = $db + $suffix; if (Test-Path -LiteralPath $side) { Remove-Item -LiteralPath $side } };" ^
  "  Write-Host ('Yedek olusturuldu: ' + $backup);" ^
  "} else { Write-Host 'Veritabani bulunamadi; yeni veritabani olusturulacak.' }"
if errorlevel 1 (
  echo Sifirlama basarisiz. NetMon'u kapatip tekrar deneyin.
  pause
  exit /b 1
)

start "" calistir.bat
