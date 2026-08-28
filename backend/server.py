"""NetMon FastAPI uygulamasının geriye uyumlu giriş noktası.

Çalışma zamanı uygulaması ``application`` modülünde tutulur. Modül nesnesini
doğrudan yeniden kullanmak, mevcut ``import server`` çağrılarının ve testlerdeki
monkeypatch işlemlerinin aynı global duruma erişmesini sağlar.
"""

import importlib
import sys


if __package__:
    _application = importlib.import_module(".application", __package__)
else:
    _application = importlib.import_module("application")

sys.modules[__name__] = _application
