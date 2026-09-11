from pathlib import Path

from backend.core.initial_access import password_file_text, write_password_file


def test_initial_password_document_is_clear_and_complete(tmp_path):
    path = tmp_path / "initial_admin_password.txt"

    content = password_file_text(username="admin", password="temporary-secret", path=path)

    assert "NETMON İLK GİRİŞ BİLGİLERİ" in content
    assert "Kullanıcı adı : admin" in content
    assert "Geçici parola : temporary-secret" in content
    assert str(path) in content
    assert "otomatik olarak silinir" in content
    assert content.splitlines()[1] == "temporary-secret"


def test_password_file_is_written_as_a_complete_document(tmp_path):
    path = tmp_path / "initial_admin_password.txt"

    write_password_file(path, username="admin", password="temporary-secret")

    assert path.is_file()
    assert path.read_text(encoding="utf-8") == password_file_text(
        username="admin", password="temporary-secret", path=path.resolve()
    )


def test_recovery_document_has_distinct_title(tmp_path):
    path = Path(tmp_path) / "initial_admin_password.txt"

    content = password_file_text(username="admin", password="new-secret", path=path, recovery=True)

    assert "NETMON YÖNETİCİ KURTARMA BİLGİLERİ" in content
