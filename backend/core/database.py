"""SQLite bağlantısı için ortak fabrika."""

import sqlite3
from pathlib import Path


def connect_sqlite(path: str | Path) -> sqlite3.Connection:
    """Yabancı anahtar denetimli ve kısa kilit beklemeli bağlantı aç."""
    connection = sqlite3.connect(path, timeout=5.0)
    connection.execute("PRAGMA foreign_keys=ON")
    return connection
