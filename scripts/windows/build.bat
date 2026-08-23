@echo off
REM ============================================================
REM  NetMon - tek tikla .exe derleme
REM  Bu dosyayi WINDOWS bilgisayarda, cift tiklayarak calistirin.
REM  (Python bir kere .exe'yi derlemek icin gerekli; ama derlenen
REM   NetMon.exe'yi baskalarina attiginizda ONLARIN Python kurmasina
REM   gerek YOK - exe tek basina calisir.)
REM ============================================================

setlocal
cd /d "%~dp0..\..\backend"

echo.
echo === [1/4] Python kontrol ediliyor ===
where python >nul 2>nul
if errorlevel 1 (
    echo HATA: Python bulunamadi. https://www.python.org/downloads/ adresinden
    echo Python 3.11 veya 3.12 kurun ve kurulumda "Add python.exe to PATH" kutusunu isaretleyin.
    pause
    exit /b 1
)

echo.
echo === [2/4] Sanal ortam olusturuluyor (venv) ===
REM Onceki yarim/bozuk bir deneme kalintisi varsa (ornegin python.exe
REM veya activate.bat eksikse) venv'i silip sifirdan kuruyoruz; aksi
REM halde "zaten var" sanip eksik paketleri atlayabiliyor.
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
)
call .buildenv\Scripts\activate.bat

echo.
echo === [3/4] Gerekli paketler kuruluyor ===
.buildenv\Scripts\python.exe -m pip install --upgrade pip >nul
.buildenv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo HATA: Paket kurulumu basarisiz oldu ^(yukaridaki kirmizi satirlara bakin^).
    echo En sik sebep: pythonnet paketi icin gerekli derleme araclari eksik.
    echo Duzeltmek icin: "Microsoft C++ Build Tools" kurun
    echo ^(https://visualstudio.microsoft.com/visual-cpp-build-tools/^)
    echo ya da requirements.txt icindeki "pythonnet" satirini silip tekrar deneyin.
    pause
    exit /b 1
)

REM PyInstaller gercekten kurulmus mu diye ayrica dogruluyoruz; pip
REM bazen bir onceki bozuk venv/cache yuzunden sessizce eksik birakabiliyor.
.buildenv\Scripts\python.exe -m PyInstaller --version >nul 2>nul
if errorlevel 1 (
    echo PyInstaller bulunamadi, ayrica kuruluyor...
    .buildenv\Scripts\python.exe -m pip install --force-reinstall pyinstaller>=6.6
    if errorlevel 1 (
        echo.
        echo HATA: PyInstaller kurulamadi.
        pause
        exit /b 1
    )
)

echo.
echo === [4/4] NetMon.exe derleniyor (bu birkac dakika surebilir) ===
REM PATH/activate sorunlarindan etkilenmemek icin venv'in kendi python'u
REM uzerinden cagiriyoruz (dogrudan "pyinstaller" komutuna guvenmek yerine).
.buildenv\Scripts\python.exe -m PyInstaller --clean --noconfirm NetMon.spec

echo.
if exist "dist\NetMon.exe" (
    echo BASARILI!  Dosya burada:  backend\dist\NetMon.exe
    echo Bu tek dosyayi baskalarina gonderebilirsiniz; calistiran kisinin
    echo Python ya da baska bir sey kurmasina gerek yoktur.
    explorer dist
) else (
    echo Derleme basarisiz oldu. Yukaridaki hata mesajini kontrol edin.
)

pause
