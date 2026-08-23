@echo off
chcp 65001 > nul
setlocal
cd /d "%~dp0..\..\"
title NetMon - Guvenli Guncelleme

where git >nul 2>nul
if errorlevel 1 (
  echo HATA: Git bulunamadi.
  pause
  exit /b 1
)

for /f %%i in ('git status --porcelain') do (
  echo HATA: Kaydedilmemis yerel degisiklikler var. Guncelleme iptal edildi.
  echo Once degisikliklerinizi commit edin veya yedekleyin.
  pause
  exit /b 1
)

echo GitHub guncellemeleri kontrol ediliyor...
git fetch origin main
if errorlevel 1 goto :failed
git pull --ff-only origin main
if errorlevel 1 goto :failed

echo Guncelleme tamamlandi. Uygulamayi calistir.bat ile baslatabilirsiniz.
pause
exit /b 0

:failed
echo Guncelleme uygulanamadi. Yukaridaki Git hatasini kontrol edin.
pause
exit /b 1
