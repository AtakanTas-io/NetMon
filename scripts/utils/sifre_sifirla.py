"""
NetMon Admin Şifre Sıfırlama Aracı
-----------------------------------
initial_admin_password.txt dosyasını kaybettiyseniz (daha önce bir kez
değiştirilip otomatik silindiği için), bu script netmon.db içindeki
"admin" kullanıcısının şifresini rastgele yeni bir şifreyle değiştirir.

KULLANIM:
  1) NetMon çalışıyorsa önce KAPATIN (veritabanı kilitli olmasın).
  2) Bu dosyayı .netmon klasörünüzün İÇİNE kopyalayın
     (netmon.db ile aynı klasöre, örn. C:\\Users\\<siz>\\.netmon\\).
  3) O klasörde bir terminal açıp şunu çalıştırın:
         python sifre_sifirla.py
  4) Ekrana yazdırılan yeni geçici şifreyle giriş yapın.
     (Giriş yaptığınızda sistem sizi yine "şifreyi değiştir" ekranına
     zorlayacak — bu normal ve NetMon'un güvenlik tasarımının bir parçası.)
"""

import hashlib
import secrets
import sqlite3
import sys
from pathlib import Path


def hash_password(password: str) -> tuple[str, str]:
    """server.py içindeki _hash_password ile birebir aynı algoritma
    (PBKDF2-HMAC-SHA256, 200.000 iterasyon) — aksi halde giriş başarısız olur."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return salt, dk.hex()


def main():
    db_path = Path(__file__).resolve().parent / "netmon.db"
    if not db_path.exists():
        print(f"HATA: netmon.db bulunamadı: {db_path}")
        print("Bu scripti netmon.db ile AYNI klasöre koyup oradan çalıştırın.")
        sys.exit(1)

    conn = sqlite3.connect(db_path, timeout=5.0)
    row = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not row:
        print("HATA: 'admin' kullanıcısı veritabanında bulunamadı.")
        conn.close()
        sys.exit(1)

    new_password = secrets.token_urlsafe(18)
    salt, pw_hash = hash_password(new_password)
    conn.execute(
        "UPDATE users SET password_hash=?, salt=?, active=1, must_change_password=1 WHERE username='admin'",
        (pw_hash, salt),
    )
    # Kilit/başarısız deneme geçmişini de temizle, sıfırlama sonrası hemen giriş engellenmesin.
    try:
        conn.execute("DELETE FROM login_attempts WHERE username='admin'")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

    print("=" * 60)
    print("Admin şifresi başarıyla sıfırlandı.")
    print("Kullanıcı adı : admin")
    print(f"Geçici şifre  : {new_password}")
    print("Bu şifreyi not alın — bir daha gösterilmeyecek.")
    print("Giriş yaptıktan hemen sonra yeni bir şifre belirlemeniz istenecek.")
    print("=" * 60)


if __name__ == "__main__":
    main()
