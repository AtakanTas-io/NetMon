# -*- mode: python ; coding: utf-8 -*-
# NetMon icin tek dosyalik (onefile) Windows .exe derleme tarifi.
# Calistirmak icin: pyinstaller NetMon.spec  (build.bat bunu otomatik yapar)

a = Analysis(
    ['desktop_app.py'],
    pathex=[],
    binaries=[],
    datas=[('../frontend', 'frontend'), ('oui.json', '.')],
    hiddenimports=[
        # server.py uygulamayi importlib ile dinamik yukler. PyInstaller bu
        # baglantiyi statik analizde goremedigi icin ana uygulamayi elle ekle.
        'application',
        'core.operations',
        'routers.operations',
        # Rapor ureticileri fonksiyon icinde tembel yuklenir.
        'openpyxl',
        'reportlab',
        # uvicorn dinamik importlari - onefile derlemede pyinstaller bunlari
        # otomatik bulamayabiliyor, elle ekliyoruz
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.loops.asyncio',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.http.h11_impl',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.protocols.websockets.wsproto_impl',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'websockets',
        'websockets.legacy',
        'websockets.legacy.client',
        'websockets.legacy.server',
        # pywebview Windows arka uclari
        'webview.platforms.winforms',
        'webview.platforms.edgechromium',
        'webview.platforms.cef',
        'clr_loader',
        'pythonnet',
        'winrm',
        'winrm.protocol',
        'paramiko',
        'wmi',
        'pythoncom',
        'win32crypt',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetMon',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
