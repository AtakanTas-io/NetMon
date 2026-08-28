# NetMon

Yerel ağdaki cihazları keşfetmek, envanterini tutmak ve temel ağ sorunlarını tek ekrandan incelemek için geliştirdiğim bir ağ yönetim uygulaması.

[![CI](https://github.com/AtakanTas-io/NetMon/actions/workflows/ci.yml/badge.svg)](https://github.com/AtakanTas-io/NetMon/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10--3.13-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-105%20passed-brightgreen?logo=pytest)
![License](https://img.shields.io/badge/license-MIT-blue)

## Neler var?

- Nmap, ARP, mDNS, SSDP ve SNMP üzerinden cihaz keşfi
- MAC adresine göre tekilleştirilmiş cihaz envanteri
- Ping, DNS, rota ve bağlantı tanılama araçları
- WMI/WinRM ile yetkili Windows envanteri
- SNMP erişimi varsa switch port eşleştirmesi
- IPAM, IP çakışması kontrolü ve subnet doluluk görünümü
- SSH ile alınan ağ cihazı yapılandırmalarının yedeği ve farkı
- Yetkili sunucu listesine göre rogue DHCP uyarısı
- Yerel ağ arayüzü trafiği ve işletim sistemindeki aktif bağlantılar
- Kullanıcı rolleri, oturum kontrolü ve işlem kayıtları
- Web arayüzü ve PyWebView masaüstü çalıştırma seçeneği

## Veri sınırları

NetMon erişemediği bilgiyi tahmin etmez. Donanım ve yazılım envanteri için hedef sistemde yetkili WMI, WinRM, SSH veya SNMP erişimi gerekir. Yerel ağ kartı sayaçları cihaz başına paket yakalama verisi sağlamaz. Açık bir port da tek başına güvenlik açığı olarak değerlendirilmez.

Bu ayrım arayüzde `ölçüldü`, `keşfedildi`, `yapılandırıldı` ve `kullanılamıyor` durumlarıyla gösterilir.

## Kurulum

Gerekenler:

- Python 3.10–3.13
- Windows masaüstü kullanımı için WebView2
- Kullanılacak özelliğe göre Nmap, SNMP, WMI/WinRM veya SSH erişimi

Windows'ta hızlı başlatma:

```cmd
calistir.bat
```

Elle çalıştırmak için:

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python backend\desktop_app.py
```

İlk açılışta yönetici parolası otomatik oluşturulur ve `%USERPROFILE%\.netmon\initial_admin_password.txt` dosyasına yazılır. İlk girişte parola değişikliği istenir.

## Platform desteği

NetMon'un FastAPI sunucusu ve tarayıcı arayüzü Windows, Linux ve macOS üzerinde çalışabilir. İşletim sistemine veya harici araçlara bağlı özellikler aşağıdaki gibidir:

| Özellik | Windows | Linux | macOS | Gereksinim / sınır |
|---|:---:|:---:|:---:|---|
| FastAPI sunucusu ve web arayüzü | Evet | Evet | Evet | Python 3.10–3.13 |
| PyWebView masaüstü kabuğu | Evet | Koşullu | Koşullu | İşletim sisteminin desteklenen WebView çalışma zamanı gerekir |
| ICMP, DNS, rota ve yerel ağ keşfi | Evet | Evet | Evet | Bazı komutlar için işletim sistemi aracı ve ek yetki gerekebilir |
| Nmap keşfi ve servis taraması | Evet | Evet | Evet | `nmap` ayrıca kurulmalı ve `PATH` içinde bulunmalı |
| WMI/DCOM envanteri | Evet | Hayır | Hayır | `wmi`, `pywin32` ve hedef Windows izinleri gerekir |
| WinRM ile Windows envanteri | Evet | Hayır | Hayır | Mevcut kurulumda `pywinrm` Windows bağımlılığıdır |
| SSH envanteri ve yapılandırma yedeği | Evet | Evet | Evet | Paramiko ve hedefte yetkili SSH hesabı gerekir |
| SNMP keşfi ve switch port eşleştirmesi | Evet | Evet | Evet | Hedef cihazda SNMP ve geçerli community gerekir |
| RDP başlatma | Evet | Hayır | Hayır | Windows Uzak Masaüstü istemcisi (`mstsc.exe`) kullanılır |
| Gizli ayarların şifrelenmesi | DPAPI | Fernet | Fernet | Windows'ta kullanıcıya bağlı DPAPI; diğerlerinde yerel anahtar dosyası |

Linux ve macOS kurulumu:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python backend/server.py
```

Windows dışındaki sistemlerde WMI, SSH ve SNMP parolaları `~/.netmon/secret.key` anahtarıyla Fernet kullanılarak şifrelenir. Anahtar dosyasının izni her kullanımda `0600` yapılır. `netmon.db` yedekleniyorsa bu dosya da güvenli ve ayrı bir konumda yedeklenmelidir; anahtar kaybolursa `fernet:` ile saklanan değerler çözülemez. Windows'taki mevcut `dpapi:` kayıtları değişmeden korunur.

## Klasörler

```text
backend/          FastAPI sunucusu ve ağ tarama modülleri
frontend/         Tarayıcı arayüzü
tests/            Pytest testleri
scripts/windows/  Başlatma, derleme ve GitHub yardımcıları
scripts/utils/    Envanter ve yönetim yardımcıları
docs/             Mimari notları ve eski test raporları
```

Kökteki `calistir.bat`, `build.bat` ve `auto-push.ps1` dosyaları `scripts/windows/` altındaki asıl komutlara yönlendirir.

## Test

```cmd
python -m pytest tests -v
```

Mevcut test paketi 105 senaryodan oluşuyor. GitHub Actions aynı paketi Windows üzerinde Python 3.10, 3.11, 3.12 ve 3.13 ile çalıştırıyor.

## Notlar

- Planlanan işler için [ROADMAP.md](ROADMAP.md)
- Değişiklik özeti için [CHANGELOG.md](CHANGELOG.md)
- Katkı süreci için [CONTRIBUTING.md](CONTRIBUTING.md)
- Güvenlik bildirimi için [SECURITY.md](SECURITY.md)

MIT lisansı ile yayımlanır.
