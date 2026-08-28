import sys
from contextlib import contextmanager
from pathlib import Path

import anyio
from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
for path in (PROJECT_ROOT, BACKEND_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


@contextmanager
def persistent_test_client(app):
    """TestClient isteklerini tek portalda çalıştır, uygulama worker'larını başlatma."""
    client = TestClient(app)
    with anyio.from_thread.start_blocking_portal(**client.async_backend) as portal:
        client.portal = portal
        try:
            yield client
        finally:
            client.portal = None
            client.close()
