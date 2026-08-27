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
