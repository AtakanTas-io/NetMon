import sys
from contextlib import contextmanager
from pathlib import Path

import anyio
import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
for path in (PROJECT_ROOT, BACKEND_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


@pytest.fixture(scope="session")
def test_portal():
    """Tüm test paketi boyunca tek AnyIO portalı kullan."""
    with anyio.from_thread.start_blocking_portal() as portal:
        yield portal


@contextmanager
def persistent_test_client(app, portal):
    """TestClient isteklerini ortak portalda çalıştır, uygulama worker'larını başlatma."""
    client = TestClient(app)
    client.portal = portal
    try:
        yield client
    finally:
        client.portal = None
        client.close()
