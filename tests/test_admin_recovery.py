import hashlib
import sqlite3
from pathlib import Path

import pytest

import backend.admin_recovery as recovery
from backend.admin_recovery import PASSWORD_HASH_ITERATIONS, recover_admin


def _database(path, *, username="admin"):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, salt TEXT,
            role TEXT, active INTEGER, must_change_password INTEGER, created_at REAL
        );
        CREATE TABLE sessions (token TEXT, user_id INTEGER, created_at REAL, expires_at REAL);
        CREATE TABLE login_attempts (username TEXT PRIMARY KEY, fail_count INTEGER, last_attempt REAL, locked_until REAL);
        CREATE TABLE audit_log (ts REAL, username TEXT, action TEXT, detail TEXT, success INTEGER);
        """
    )
    conn.execute("INSERT INTO users VALUES (1, ?, 'old-hash', 'old-salt', 'admin', 0, 0, 1)", (username,))
    conn.execute("INSERT INTO sessions VALUES ('old-token', 1, 1, 9999999999)")
    conn.execute("INSERT INTO login_attempts VALUES (?, 5, 1, 9999999999)", (username,))
    conn.commit()
    conn.close()


def test_recovery_backs_up_database_and_invalidates_old_access(tmp_path):
    database = tmp_path / "netmon.db"
    output = tmp_path / "temporary-password.txt"
    _database(database)

    result = recover_admin(database, output=output)

    assert result["backup"].is_file()
    assert output.is_file()
    password = output.read_text(encoding="utf-8").splitlines()[1]
    conn = sqlite3.connect(database)
    user = conn.execute(
        "SELECT password_hash, salt, active, must_change_password FROM users WHERE username='admin'"
    ).fetchone()
    sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    attempts = conn.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
    audit = conn.execute("SELECT action, detail, success FROM audit_log").fetchone()
    conn.close()

    expected = hashlib.pbkdf2_hmac("sha256", password.encode(), user[1].encode(), PASSWORD_HASH_ITERATIONS).hex()
    assert user == (f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${expected}", user[1], 1, 1)
    assert sessions == 0
    assert attempts == 0
    assert audit == ("admin_password_recovery", "hesap=admin", 1)


def test_recovery_rejects_unknown_user_without_creating_backup(tmp_path):
    database = tmp_path / "netmon.db"
    _database(database)

    with pytest.raises(ValueError, match="Kullanıcı bulunamadı"):
        recover_admin(database, username="missing")

    assert not list(tmp_path.glob("*.bak"))


def test_recovery_rolls_back_when_password_file_cannot_be_written(tmp_path, monkeypatch):
    database = tmp_path / "netmon.db"
    output = tmp_path / "temporary-password.txt"
    _database(database)
    output.write_text("previous", encoding="utf-8")

    def fail_write(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(recovery, "write_password_file", fail_write)
    with pytest.raises(OSError, match="disk full"):
        recover_admin(database, output=output)

    conn = sqlite3.connect(database)
    user = conn.execute(
        "SELECT password_hash, salt, active, must_change_password FROM users WHERE username='admin'"
    ).fetchone()
    conn.close()
    assert user == ("old-hash", "old-salt", 0, 0)
    assert output.read_text(encoding="utf-8") == "previous"


def test_windows_recovery_script_targets_packaged_user_profile():
    script = (Path(__file__).parents[1] / "scripts" / "windows" / "yonetici-parolasi-kurtar.bat").read_text(
        encoding="utf-8"
    )

    assert "%USERPROFILE%\\.netmon" in script
    assert '--database "%NETMON_USER_DATA%\\netmon.db"' in script
    assert 'notepad "%NETMON_USER_DATA%\\initial_admin_password.txt"' in script
