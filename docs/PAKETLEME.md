# Temiz kaynak paketi

Proje kökünde Windows PowerShell ile çalıştırın:

```powershell
powershell -NoProfile -File .\scripts\windows\package_release.ps1
```

ZIP, `dist/NetMon-source-TARIH-SAAT.zip` yoluna yazılır. Farklı bir çıktı yolu için:

```powershell
powershell -NoProfile -File .\scripts\windows\package_release.ps1 -OutputPath C:\Paketler\NetMon-source.zip
```

Mevcut bir ZIP'in üzerine yazılmaz; yeni bir dosya adı seçin.

Paket yalnız `backend/`, `frontend/`, `tests/`, `docs/` ve kökteki README, CHANGELOG,
CONTRIBUTING, SECURITY, ROADMAP ve LICENSE belgelerini içerir. Kaynak dosyaları çalışma
ağacından alınır; henüz commitlenmemiş değişiklikler de pakete girer.

Her derinlikte `.buildenv/`, `.git/`, `pytest_temp*/`, `netmon.db*`, `.coverage*`,
`__pycache__/`, `build/`, `dist/`, sanal ortamlar, `.env*`, veritabanları, gizli anahtarlar,
loglar ve derlenmiş Python/Windows dosyaları dışarıda bırakılır. Sembolik bağlantılar
ve Windows junction bağlantıları izlenmez.

Bu ZIP bir kaynak arşividir. Windows çalıştırılabilir dosyası için mevcut
`scripts/windows/build.bat` ve release iş akışı kullanılır.
