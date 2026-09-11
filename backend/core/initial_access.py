"""İlk giriş ve yönetici kurtarma bilgilerini güvenli bir yerel dosyaya yazar."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def password_file_text(*, username: str, password: str, path: Path, recovery: bool = False) -> str:
    title = "NETMON YÖNETİCİ KURTARMA BİLGİLERİ" if recovery else "NETMON İLK GİRİŞ BİLGİLERİ"
    return (
        f"{title}\n"
        f"{password}\n\n"
        f"Kullanıcı adı : {username}\n"
        f"Geçici parola : {password}\n\n"
        "NetMon giriş ekranında yukarıdaki bilgileri kullanın.\n"
        "İlk girişten hemen sonra kendi parolanızı belirlemeniz istenir.\n"
        "Parola başarıyla değiştirildiğinde bu dosya otomatik olarak silinir.\n\n"
        f"Bu dosyanın konumu: {path}\n"
    )


def write_password_file(path: Path, *, username: str, password: str, recovery: bool = False) -> None:
    """Parola belgesini aynı dizinde atomik olarak oluşturup yerine koyar."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(password_file_text(username=username, password=password, path=path, recovery=recovery))
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
