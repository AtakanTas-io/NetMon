"""
NetMon'u tarayici sekmesi yerine gercek bir masaustu penceresinde acar.

Ayni backend'i (server.py) kullanir; yani pencerede gordugunuz her sey
tarayicidaki ile birebir aynidir. Fark sadece kabuktur.

Calistirma:
    python desktop_app.py
"""

import os
import socket
import sys
import threading
import time

# --- PyInstaller --noconsole (pencereli) modda kritik duzeltme -----------
# Konsolsuz calisan bir .exe'de sys.stdout / sys.stderr None olur. uvicorn'un
# varsayilan log yapilandirmasi ("default" formatter) stdout.isatty() cagirir;
# stdout None ise bu "AttributeError: 'NoneType' object has no attribute
# 'isatty'" -> "Unable to configure formatter 'default'" hatasiyla programin
# acilista cokmesine sebep olur. Cozum: stdout/stderr None ise once devnull'a
# yonlendir, ustune uvicorn'a hic log yapilandirmasi verdirme (log_config=None).
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")
# ---------------------------------------------------------------------------

import uvicorn

import server                      # tum API'ler, WebSocket ve arka plan servisleri burada

HOST = "127.0.0.1"


def find_free_port(preferred: int = 8000) -> int:
    """8000 doluysa (baska bir NetMon acikken) bos bir port bul."""
    for port in [preferred] + list(range(8001, 8030)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((HOST, port))
                return port
            except OSError:
                continue
    return 0  # isletim sistemi secsin


def wait_until_up(port: int, timeout: float = 15.0) -> bool:
    """Sunucu ayaga kalkmadan pencereyi acmayalim; yoksa bos sayfa gorunur."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main():
    port = find_free_port()

    config = uvicorn.Config(
        server.app,
        host=HOST,
        port=port,
        log_level="error",
        access_log=False,
        log_config=None,  # dictConfig'i tamamen atla -> yukaridaki hatayi kokten onler
    )
    http = uvicorn.Server(config)
    threading.Thread(target=http.run, daemon=True).start()

    url = f"http://{HOST}:{port}"
    if not wait_until_up(port):
        print(f"Sunucu baslatilamadi. Elle deneyin: python server.py -> {url}")
        sys.exit(1)

    try:
        import webview
    except ImportError:
        # pywebview kurulu degilse en azindan tarayicida acalim
        import webbrowser
        print(f"pywebview bulunamadi, tarayicida aciliyor: {url}")
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return

    window = webview.create_window(
        title="NetMon — Ağ İzleme",
        url=url,
        width=1500,
        height=940,
        min_size=(1100, 720),
        background_color="#080d16",
    )

    def on_closed():
        # DÜZELTME: server.py'deki durdurma olayının gerçek adı _stop_event.
        # Burada yanlış isimle (server._stop) çağrılıyordu; bu isimde bir
        # öznitelik server.py'de hiç yok, dolayısıyla pencere kapatılırken
        # AttributeError fırlatılıyordu (arka plan thread'leri sessizce
        # çalışmaya devam ediyordu, program .exe olarak arka planda asılı
        # kalabiliyordu).
        server._stop_event.set()

    window.events.closed += on_closed

    # Tarayıcı önbelleğinin silinmemesi için gizli modu (private_mode) kapatıyoruz.
    # Çerezler (Beni Hatırla token'ı) ve LocalStorage verileri bu klasörde saklanacak.
    # Test/kurumsal kurulumlarda NETMON_DATA_DIR kullanildiginda WebView
    # verilerini de ayni izole dizinde tut. Normal kullanimda USER_DATA_DIR
    # zaten kullanicinin ~/.netmon dizinidir.
    storage_dir = os.path.join(str(server.USER_DATA_DIR), "webview_data")
    os.makedirs(storage_dir, exist_ok=True)

    webview.start(private_mode=False, storage_path=storage_dir)


if __name__ == "__main__":
    main()
