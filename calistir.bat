@echo off
REM Gelistirme/onizleme icin: .exe derlemeden dogrudan uygulamayi acar.
setlocal
cd /d "%~dp0backend"

if exist ".buildenv" (
    if not exist ".buildenv\Scripts\python.exe" (
        echo Eksik/bozuk bir onceki kurulum bulundu, temizleniyor...
        rmdir /s /q ".buildenv"
    ) else (
        .buildenv\Scripts\python.exe -c "import sys" >nul 2>nul
        if errorlevel 1 (
            echo Baska bilgisayardan kalmis bozuk sanal ortam bulundu, yenileniyor...
            rmdir /s /q ".buildenv"
        )
    )
)
if not exist ".buildenv" (
    python -m venv .buildenv
    if errorlevel 1 goto :venv_failed
)
call .buildenv\Scripts\activate.bat

REM Her acilista temel bagimliliklari hizlica dogrula. Eksikse kur;
REM boylece baska bilgisayardan tasinan yarim bir .buildenv uygulamayi
REM sessizce dusurmez.
.buildenv\Scripts\python.exe -c "import fastapi, uvicorn" >nul 2>nul
if errorlevel 1 (
    echo Eksik Python paketleri bulundu, requirements kuruluyor...
    .buildenv\Scripts\python.exe -m pip install -r requirements.txt
    if errorlevel 1 goto :deps_failed
)

REM pythonw.exe konsolsuz calisir; boylece surec bu cmd penceresine bagli
REM olmaz ve pencereyi kapatmak uygulamayi kapatmaz. pythonw yoksa (bazi
REM minimal Python kurulumlarinda olabilir) normal python.exe'ye dusulur.
if exist ".buildenv\Scripts\pythonw.exe" (
    start "" ".buildenv\Scripts\pythonw.exe" desktop_app.py
) else (
    start "" ".buildenv\Scripts\python.exe" desktop_app.py
)
exit /b 0

:venv_failed
echo HATA: Python sanal ortami olusturulamadi.
pause
exit /b 1

:deps_failed
echo HATA: Python bagimliliklari kurulamadi.
pause
exit /b 1

:app_failed
echo HATA: NetMon baslatilamadi. Yukaridaki hata mesajini kontrol edin.
pause
exit /b 1
