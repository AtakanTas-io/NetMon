<div align="center">
  <!-- Eğer bir logonuz varsa buraya ekleyebilirsiniz, örneğin: <img src="frontend/assets/logo.png" width="120" /> -->
  <h1>🌐 NetMon</h1>
  <h3>Siber Topoloji & Ağ Varlık İzleme Sistemi</h3>

  <p align="center">
    <strong>Yerel ağınızdaki cihazları keşfedin, canlı trafiği izleyin ve derin envanter taraması yapın.</strong>
  </p>

  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
    <img src="https://img.shields.io/badge/PyWebView-5.0+-8A2BE2?style=for-the-badge&logo=python&logoColor=white" alt="PyWebView">
    <img src="https://img.shields.io/badge/License-MIT-4CAF50?style=for-the-badge" alt="License">
    <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-555555?style=for-the-badge&logo=windows&logoColor=white" alt="Platform">
  </p>
</div>

<hr/>

**NetMon**, yerel ağınızdaki tüm cihazları ajansız (agentless) keşfeden, canlı trafik ve hop-by-hop rotalama akışlarını görselleştiren, WMI/SNMP yetkili envanter taraması ve siber topoloji haritası sunan modern bir masaüstü ve web izleme uygulamasıdır.

## 🌟 Öne Çıkan Özellikler

- 🌌 **NetTak Siber Topoloji Haritası:** Ağdaki cihazları dairesel siber podlar, durum aurası ve entegre kategori sütunları (Ağ Cihazları, Bilgisayarlar, Mobil Cihazlar, IoT) halinde dinamik görselleştirme.
- 🌐 **Hop-by-Hop Canlı İnternet Rota Akışı:** Seçilen cihazın `WAN (İnternet) ➔ Gateway (Modem) ➔ Hedef Cihaz` arasındaki anlık paket iletimini canlı neon ışımalar ve gecikme metrikleri ile gösterim.
- 🤖 **Akıllı Otomatik Profilleme (Fingerprinting):** OUI MAC satıcı imzaları, mDNS (Bonjour), SSDP (UPnP) ve TTL verileriyle mobil cihazların (iOS/Android), Smart TV'lerin ve IoT donanımlarının profillerini otomatik çıkarma.
- 🔑 **WMI / WinRM Derin Envanter Taraması:** Windows bilgisayar ve sunucuların CPU modeli, çekirdek sayısı, RAM kapasitesi, GPU, anakart, disk kullanımı ve yüklü program/servis listesini çekme.
- 📊 **NMS Dairesel Radyal Göstergeler & Canlı Grafik:** Anlık internet bant genişliği (Upload/Download Mbps) ve ağ durum sayaçları.
- ⚡ **Tamamen Taşınabilir Masaüstü Kabuğu (PyWebView):** Bağımsız masaüstü uygulama penceresinde veya web browser üzerinde çalıştırma seçeneği.

## 🏗️ Proje Mimarisi

```text
NetMon/
├── backend/             # Python FastAPI Backend & Ağ Keşif Motoru
│   ├── server.py        # FastAPI REST & WebSocket Servis Motoru
│   └── desktop_app.py   # PyWebView Masaüstü Pencere Kabuğu
├── frontend/            # Web Arayüzü (HTML/CSS/JS)
├── tests/               # Otomatik CI/CD Testleri (Güvenlik, Envanter)
└── build.bat            # Windows için paketleme betiği
```

## 🚀 Kurulum ve Çalıştırma

**Sistem Gereksinimleri:** Windows 10/11 veya Windows Server, Python 3.11/3.12.

**En Kolay Yöntem:**
Kök dizindeki çalıştırıcı betiği kullanarak tüm bağımlılıkları ve sanal ortamı otomatik kurabilirsiniz:
```cmd
calistir.bat
```

<details>
<summary><b>Manuel Kurulum için tıklayın</b></summary>

```cmd
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe backend\desktop_app.py
```
</details>

> [!IMPORTANT]
> **Güvenlik Notu:** İlk kurulumda sabit bir yönetici parolası kullanılmaz. Rastgele parola şu dosyaya yazılır: `%USERPROFILE%\.netmon\initial_admin_password.txt`. Kullanıcı adı `admin`'dir. İlk girişte parola değişimi zorunludur.

---

## 🔐 Derin Ağ Envanteri ve Yetkilendirme

NetMon'un bir bilgisayarı ağda görmesi, donanım/yazılım envanterini otomatik paylaşacağı anlamına gelmez. Hedefte **WMI/DCOM** veya **WinRM** erişimi ve bunu kullanmaya yetkili bir hesap bulunmalıdır.

| Hedef | Protokol | Alınabilen Bilgiler |
|---|---|---|
| **Windows İstemci/Sunucu** | WinRM/CIM veya WMI/DCOM | Bilgisayar adı, OS, CPU, RAM, GPU, anakart, diskler, kurulu programlar, aktif kullanıcı, Defender/AV ve güvenlik duvarı |
| **Linux** | SSH | Host/OS/kernel, mimari, CPU/çekirdek, RAM, üretici/model, diskler, paketler, aktif kullanıcı |
| **Ağ Cihazları (Router vb.)** | SNMP (Salt-okuma) | `sysName`, `sysDescr` ve cihazın desteklediği ölçüde temel sistem kimliği |
| **IoT / Mobil / Tablet** | Ajansız Keşif | IP, MAC, üretici, hostname ve gözlenen servisler (mDNS, SSDP vb.) |

<details>
<summary><b>Şirket Kurulumu & Windows Cihazlardan Bilgi Alma (Genişlet)</b></summary>

1. Etki alanında (Domain) yalnızca gerekli WMI/CIM sınıflarını okuyabilen ayrı bir envanter servis hesabı oluşturun.
2. WinRM'i tercihen Grup İlkesi (GPO) ile etkinleştirin. HTTPS/5986 kullanıyorsanız kurumsal CA sertifikası dağıtın.
3. Alternatif WMI/DCOM yolu için hedeflerde Windows Management Instrumentation güvenlik duvarı kurallarını açın (TCP 135 ve RPC dinamik portları).
4. Ağ profilinin şirket ağında `DomainAuthenticated` veya uygun bir `Private` profil olduğundan emin olun.
5. NetMon'da **Ayarlar → Yetkili Envanter Kimlik Bilgileri** bölümüne `DOMAIN\kullanıcı` biçiminde hesabı girin.
6. **Cihazlar → Yetkili Envanter** ile tek hedefi sınayın; ardından **Ağı Tara** ile toplu derin tarama yapın.

**Hızlı Bağlantı Kontrolleri (Powershell):**
```powershell
Test-NetConnection 192.168.1.50 -Port 5985
Test-NetConnection 192.168.1.50 -Port 135
Test-WSMan 192.168.1.50
```
</details>

## 🛡️ Güvenlik ve Mimari Prensipleri

- **Lokal Çalışma:** Sunucu varsayılan olarak yalnız `127.0.0.1:8000` üzerinde dinler.
- **Şifreleme:** WMI, SSH ve SNMP gizli değerleri Windows DPAPI ile kullanıcı/makineye bağlı şifrelenir.
- **Güvenli Saklama:** Kullanıcı parolaları PBKDF2-HMAC-SHA256 ile salt'lı saklanır. Gizli değerler ayar API'sinde gösterilmez.
- **Sınırlandırma:** Hedef IP'ler özel/yerel IPv4 aralığıyla sınırlandırılır. Harici genel IP sorgusu varsayılan olarak kapalıdır.

## 🔄 Sürekli Entegrasyon (CI/CD)

Proje, tam otomatik Sürekli Entegrasyon altyapısına sahiptir. Kodlarınızdaki güncellemeleri GitHub'a yüklemek için:
```powershell
.\auto-push.ps1
```
Yükleme sonrasında `tests/` klasöründeki 80+ güvenlik ve envanter testi GitHub Actions üzerinde otomatik olarak çalıştırılır.

---
<div align="center">
  <sub>Geliştiren <a href="https://github.com/AtakaanShiva">AtakaanShiva</a> | <a href="LICENSE">MIT Lisansı</a> ile sunulmaktadır.</sub>
</div>
