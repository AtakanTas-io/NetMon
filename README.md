# NetMon — Ağ Keşfi ve Yetkili Cihaz Envanteri

NetMon, Windows üzerinde çalışan yerel bir ağ izleme uygulamasıdır. Cihazları ARP, ICMP, DNS, mDNS, SSDP ve servis kanıtlarıyla keşfeder; ayrıntılı envanteri ise yalnızca yetkili yönetim protokollerinden alır.

Tahmini CPU, RAM, disk, antivirüs veya güvenlik duvarı bilgisi üretilmez. Bir hedef ayrıntılı bilgi paylaşmıyorsa arayüz bunu açıkça “doğrulanamadı” olarak gösterir.

## Desteklenen envanter yolları

| Hedef | Protokol | Alınabilen bilgiler |
|---|---|---|
| Windows istemci/sunucu | WinRM/CIM veya WMI/DCOM | Bilgisayar adı, işletim sistemi, CPU, RAM, GPU, anakart, diskler, kurulu programlar, aktif kullanıcı; erişilebildiğinde Defender/AV ve güvenlik duvarı |
| Linux | SSH | Host/OS/kernel, mimari, CPU/çekirdek, RAM, üretici/model/seri no, diskler, paketler, aktif kullanıcı ve güvenlik duvarı çıktısı |
| Router/switch/AP/yazıcı | SNMP salt-okuma | `sysName` ve `sysDescr`; cihazın desteklediği ölçüde temel sistem kimliği |
| Telefon/tablet/kapalı IoT | Ajansız keşif | IP, MAC, üretici, hostname ve gözlenen servisler. Donanım/yazılım ayrıntısı için MDM, üretici API'si veya cihaz ajanı gerekir. |

Başarılı yetkili envanter sonuçları SQLite'a yazılır; sonraki ağ keşfinde kaybolmaz. MAC adresi varsa cihaz IP değiştirse de son doğrulanmış envanter eşleştirilebilir.

## Kurulum ve çalıştırma

Gereksinim: Windows 10/11 veya Windows Server ve Python 3.11/3.12.

En kolay yöntem:

```cmd
calistir.bat
```

Betik bozuk veya başka bilgisayardan kopyalanmış `.buildenv` ortamını algılar, yeniden oluşturur ve bağımlılıkları kurar.

Elle çalıştırmak için:

```cmd
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe backend\desktop_app.py
```

İlk kurulumda sabit bir yönetici parolası kullanılmaz. Rastgele parola şu dosyaya yazılır:

```text
%USERPROFILE%\.netmon\initial_admin_password.txt
```

Kullanıcı adı `admin`'dir. İlk girişte parola değişimi zorunludur ve başarılı değişimden sonra dosya silinir. Eski kurulum hâlâ `admin1234` kullanıyorsa uygulama mevcut hesabı silmez, fakat parola değişimini zorunlu kılar.

## Diğer Windows cihazlardan bilgi alma

NetMon'un bir bilgisayarı ağda görmesi, o bilgisayarın donanım/yazılım envanterini otomatik paylaşacağı anlamına gelmez. Hedefte WMI/DCOM veya WinRM erişimi ve bunu kullanmaya yetkili bir hesap bulunmalıdır.

Önerilen şirket kurulumu:

1. Etki alanında yalnızca gerekli WMI/CIM sınıflarını okuyabilen ayrı bir envanter servis hesabı oluşturun. Günlük kullanıcı veya Domain Admin hesabı kullanmayın.
2. WinRM'i tercihen Grup İlkesi ile etkinleştirin. HTTPS/5986 kullanıyorsanız kurumsal CA sertifikası dağıtın; sertifika doğrulama varsayılan olarak açıktır. HTTP/5985 kullanılıyorsa yalnız güvenilir yönetim VLAN'ından erişime izin verin.
3. Alternatif WMI/DCOM yolu için hedeflerde Windows Management Instrumentation güvenlik duvarı kurallarını açın. TCP 135'in yanında RPC dinamik portları da hedef güvenlik duvarından, yalnız NetMon bilgisayarının IP'sine izinli olmalıdır.
4. Ağ profilinin şirket ağında `DomainAuthenticated` veya uygun bir `Private` profil olduğundan emin olun. Public profilde yönetim kuralları çoğunlukla kapalıdır.
5. NetMon'da **Ayarlar → Yetkili Envanter Kimlik Bilgileri** bölümüne `DOMAIN\kullanıcı` biçiminde hesabı girin. Parola Windows DPAPI ile şifrelenir ve API'den geri okunmaz.
6. **Cihazlar → Yetkili Envanter** ile tek hedefi sınayın; ardından **Ağı Tara** ile toplu derin tarama yapın.

Tarayıcı bilgisayarında hızlı bağlantı kontrolleri:

```powershell
Test-NetConnection 192.168.1.50 -Port 5985
Test-NetConnection 192.168.1.50 -Port 135
Test-WSMan 192.168.1.50
```

Yaygın hata anlamları:

- `management_ports_closed`: cihaz kapalı, farklı VLAN'da/ACL arkasında veya WMI/WinRM güvenlik duvarından engelleniyor.
- `access_denied`: hesap/parola yanlış ya da hesap WMI/CIM okumaya yetkili değil.
- `rpc_unavailable`: TCP 135 görülse bile RPC dinamik portları, DCOM veya hedef WMI servisi engelli olabilir.
- `timeout`: hedef/EDR bağlantıyı sessizce düşürüyor ya da WMI sorgusu yanıt vermiyor.

Workgroup cihazlarında yerel yönetici hesabına uygulanan Remote UAC filtresi erişimi sınırlayabilir. UAC'yi veya filtreyi ağ genelinde kapatmak yerine etki alanı hesabı, Just Enough Administration, WinRM HTTPS ve kapsamı dar güvenlik duvarı kuralları tercih edilmelidir.

## Linux ve ağ cihazları

Linux hedeflerde SSH hesabını en az yetkiyle oluşturun. NetMon bilinmeyen SSH host anahtarlarını otomatik kabul etmez; hedefe ilk kez işletim sisteminin `ssh` istemcisiyle bağlanıp parmak izini doğrulayarak `known_hosts` kaydını oluşturun.

SNMP için yalnız salt-okuma community kullanın ve ACL'yi NetMon IP'siyle sınırlandırın. Mevcut yerleşik sorgu SNMP community tabanlı temel kimlik bilgisi içindir; kritik kurumsal ağlarda SNMPv3 veya üreticinin HTTPS API'si tercih edilmelidir.

## Güvenlik davranışı

- Sunucu varsayılan olarak yalnız `127.0.0.1:8000` üzerinde dinler.
- WMI, SSH ve SNMP gizli değerleri Windows DPAPI ile kullanıcı/makineye bağlı şifrelenir.
- Gizli değerler ayar API'sinde, WebSocket URL'sinde veya audit kayıtlarında gösterilmez.
- Kullanıcı parolaları PBKDF2-HMAC-SHA256 ile salt'lı saklanır; geçici parolalar ilk girişte değiştirilir.
- Ağ değiştiren komutlar ve yetkili taramalar yalnız yönetici rolüne açıktır.
- Hedef IP'ler özel/yerel IPv4 aralığıyla, subnet listesi en fazla 16 ve en geniş `/16` ile sınırlandırılır.
- Harici genel IP sorgusu varsayılan olarak kapalıdır.

Uygulamayı LAN'a açmak için `NETMON_HOST` kullanılabilir; bu durumda ters proxy üzerinde TLS, istemci erişim kontrolü ve ek ağ güvenlik duvarı zorunlu kabul edilmelidir.

Veritabanı ve ilk-parola dosyasını farklı bir kurumsal veri dizinine almak için uygulamayı başlatmadan önce `NETMON_DATA_DIR` ortam değişkeni ayarlanabilir.

## Sürekli Entegrasyon (CI/CD) ve Otomasyon

Proje, GitHub Actions kullanılarak tam otomatik Sürekli Entegrasyon altyapısına kavuşturulmuştur. Kodlarınızdaki güncellemeleri GitHub'a yüklemek için kök dizindeki betiği kullanabilirsiniz:

```powershell
.\auto-push.ps1
```
Bu betik dosyalarınızı GitHub (AtakaanShiva/Netmon) deponuza aktarır. Yükleme sonrasında `tests/` klasöründeki 80+ adet güvenlik, envanter ve analiz testi bulutta otomatik olarak çalıştırılır. Böylece üretim (production) hatalarının önüne geçilir.

## Test ve paketleme

```cmd
python -m pip install -r requirements-dev.txt
python -m pytest -q
build.bat
```

`build.bat`, `backend\dist\NetMon.exe` üretir. Testler canlı kullanıcı veritabanını kullanmaz.

## Sınırlar

Ajansız bir tarayıcı, telefonların veya yönetim servisi kapalı bilgisayarların CPU/RAM/yazılım listesini ağdan güvenilir biçimde çıkaramaz. Böyle hedefler için şirket MDM/RMM entegrasyonu ya da küçük, imzalı bir NetMon ajanı ayrı bir dağıtım bileşeni olarak gerekir.

Lisans: [MIT](LICENSE)
