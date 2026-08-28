import os
import sqlite3
import stat

import server


def _use_non_windows_storage(monkeypatch, tmp_path):
    monkeypatch.setattr(server.platform, "system", lambda: "Linux")
    monkeypatch.setattr(server, "USER_DATA_DIR", tmp_path)


def test_fernet_secret_round_trip_uses_user_key(monkeypatch, tmp_path):
    _use_non_windows_storage(monkeypatch, tmp_path)
    secret = "Linux-Inventory-Secret!"

    protected = server._protect_secret(secret)

    assert protected.startswith("fernet:")
    assert secret not in protected
    assert server._unprotect_secret(protected) == secret
    assert (tmp_path / server.FERNET_KEY_FILENAME).is_file()


def test_fernet_key_permissions_are_owner_only_on_posix(monkeypatch, tmp_path):
    _use_non_windows_storage(monkeypatch, tmp_path)
    server._protect_secret("permission-check")

    if os.name != "nt":
        mode = stat.S_IMODE((tmp_path / server.FERNET_KEY_FILENAME).stat().st_mode)
        assert mode == 0o600


def test_fernet_record_can_be_read_regardless_of_current_platform(monkeypatch, tmp_path):
    _use_non_windows_storage(monkeypatch, tmp_path)
    protected = server._protect_secret("portable-record")

    monkeypatch.setattr(server.platform, "system", lambda: "Windows")

    assert server._unprotect_secret(protected) == "portable-record"


def test_invalid_fernet_record_is_not_returned_as_plain_text(monkeypatch, tmp_path, caplog):
    _use_non_windows_storage(monkeypatch, tmp_path)
    server._load_or_create_fernet_key()

    assert server._unprotect_secret("fernet:not-a-valid-token") == ""
    assert "Fernet ile kayıtlı gizli ayar çözülemedi" in caplog.text


def test_dpapi_record_is_preserved_but_not_readable_without_dpapi(monkeypatch, tmp_path):
    _use_non_windows_storage(monkeypatch, tmp_path)

    assert server._unprotect_secret("dpapi:ZmFrZQ==") == ""


def test_init_db_does_not_reencrypt_existing_fernet_record(monkeypatch, tmp_path):
    _use_non_windows_storage(monkeypatch, tmp_path)
    db_path = tmp_path / "netmon-test.db"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", tmp_path / "initial-admin.txt")
    server.init_db()
    server.set_setting("ssh_password", "stored-once")

    with sqlite3.connect(db_path) as conn:
        first_value = conn.execute("SELECT value FROM settings WHERE key='ssh_password'").fetchone()[0]

    server.init_db()

    with sqlite3.connect(db_path) as conn:
        second_value = conn.execute("SELECT value FROM settings WHERE key='ssh_password'").fetchone()[0]
    assert first_value.startswith("fernet:")
    assert second_value == first_value
    assert server.get_all_settings()["ssh_password"] == "stored-once"
