"""Yerel NetMon yönetici hesabını veri kaybı olmadan kurtarır."""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from .core.config import load_config as _load_config
except ImportError:
    from core.config import load_config as _load_config  # type: ignore[no-redef]


PASSWORD_HASH_ITERATIONS = 600_000


def _hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PASSWORD_HASH_ITERATIONS
    ).hex()
    return salt, f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${digest}"


def _write_private_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(content, encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def recover_admin(database: Path, username: str = "admin", output: Path | None = None) -> dict[str, object]:
    """Hesabı etkinleştir, geçici parola üret ve eski oturumları geçersiz kıl."""
    database = database.expanduser().resolve()
    if not database.is_file():
        raise ValueError(f"Veritabanı bulunamadı: {database}")

    output = (output or database.with_name("initial_admin_password.txt")).expanduser().resolve()
    if output == database:
        raise ValueError("Parola dosyası veritabanının üzerine yazılamaz.")

    conn = sqlite3.connect(database, timeout=10.0)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "users" not in tables:
            raise ValueError("Bu dosya geçerli bir NetMon veritabanı değil: users tablosu yok.")
        row = conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            raise ValueError(f"Kullanıcı bulunamadı: {username}")

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup = database.with_name(f"{database.name}.recovery-{stamp}.bak")
        backup_conn = sqlite3.connect(backup)
        try:
            conn.backup(backup_conn)
        finally:
            backup_conn.close()

        password = secrets.token_urlsafe(18)
        salt, password_hash = _hash_password(password)
        now = time.time()
        previous_output = output.read_bytes() if output.exists() else None
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE users SET password_hash=?, salt=?, active=1, must_change_password=1 WHERE id=?",
                (password_hash, salt, row[0]),
            )
            if "sessions" in tables:
                conn.execute("DELETE FROM sessions WHERE user_id=?", (row[0],))
            if "login_attempts" in tables:
                conn.execute("DELETE FROM login_attempts WHERE username=?", (username,))
            if "audit_log" in tables:
                columns = {item[1] for item in conn.execute("PRAGMA table_info(audit_log)")}
                if {"ts", "username", "action", "detail", "success"}.issubset(columns):
                    conn.execute(
                        "INSERT INTO audit_log (ts, username, action, detail, success) VALUES (?, ?, ?, ?, ?)",
                        (now, "local-recovery", "admin_password_recovery", f"hesap={username}", 1),
                    )
            _write_private_file(
                output,
                "NetMon temporary admin password (change after first login):\n" + password + "\n",
            )
            conn.commit()
        except Exception:
            conn.rollback()
            try:
                if previous_output is None:
                    output.unlink(missing_ok=True)
                else:
                    output.write_bytes(previous_output)
            except OSError:
                pass
            raise

        return {"database": database, "backup": backup, "output": output, "username": username}
    finally:
        conn.close()


def _parser() -> argparse.ArgumentParser:
    config = _load_config()
    parser = argparse.ArgumentParser(description="NetMon yerel yönetici hesabı için geçici parola üretir.")
    parser.add_argument("--database", type=Path, default=config.db_path, help="NetMon SQLite veritabanı")
    parser.add_argument("--username", default="admin", help="Kurtarılacak yerel kullanıcı (varsayılan: admin)")
    parser.add_argument("--output", type=Path, default=None, help="Geçici parolanın yazılacağı dosya")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = recover_admin(args.database, args.username, args.output)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return 1
    print(f"Hesap kurtarıldı: {result['username']}")
    print(f"Geçici parola dosyası: {result['output']}")
    print(f"Veritabanı yedeği: {result['backup']}")
    print("Girişten sonra parola değişikliği zorunludur.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
