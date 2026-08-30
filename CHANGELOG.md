# Değişiklik günlüğü

Bu dosya [Keep a Changelog](https://keepachangelog.com/tr-TR/1.1.0/) düzenini izler. Sürümler [Semantic Versioning](https://semver.org/lang/tr/) yaklaşımıyla numaralandırılır.

## [Henüz yayımlanmadı]

### Eklendi

- Ağ topolojisi cihaz durumu ve port bağlantılarını gösteren, büyük ağlarda otomatik sadeleşen etkileşimli node-link haritasına dönüştürüldü.
- Canlı alarm sayacı, kullanıcıya özel kalıcı okundu ve bastırma durumları olan alarm gelen kutusu eklendi.
- Dashboard, cihaz listesi ve topoloji yenilemeleri WebSocket push akışına taşındı; polling yalnızca bağlantı koptuğunda emniyet yenilemesi olarak bırakıldı.
- NCM karşılaştırması jsdiff ile satır bazında renklendirildi ve uzun değişmeyen bloklar açılabilir özetlere dönüştürüldü.

## [2.5.0] - 2026-08-30

### Eklendi

- Windows dışındaki sistemlerde gizli ayarlar için Fernet tabanlı yerel şifreleme eklendi.
- Desteklenen işletim sistemi ve özellik gereksinimleri README'de açıklandı.
- WMI, DHCP, SNMP switch eşleme ve derin keşif motorları için hata yolu testleri ile yüzde 70 coverage kapısı eklendi.
- Windows/Ubuntu test matrisi, Ruff/Mypy, Bandit, `pip-audit`, Dependabot ve Codecov iş akışları eklendi.
- `v*` etiketlerinde PyInstaller ile Windows uygulaması ve SHA256 özeti yayımlayan release iş akışı eklendi.
- GitHub dal koruması, zorunlu kontroller ve sürüm adımları için kurulum belgesi eklendi.
- Trafik ekranına ölçüm kaynağı ve veri yaşı eklendi.
- Sistem bileşenlerinin hazırlık durumunu döndüren API eklendi.
- DHCP ve Active Directory ayarları kalıcı hale getirildi.
- Cihaz sahibi bilgisi envantere kaydedildi.
- Operasyon ve ayar akışları için yeni testler eklendi.
- Kanıta dayalı alarm kuralları, SMTP ve yönetici tanımlı webhook teslimi eklendi.
- 24 saat, 7 gün ve 30 günlük operasyon snapshot geçmişi eklendi.
- PDF/Excel dışa aktarma ve zamanlanmış e-posta raporları eklendi.
- Subnet tabanlı çoklu site yönetimi eklendi.
- Rol kapsamlı, süreli, iptal edilebilir ve hız sınırlı API anahtarları eklendi.

### Değiştirildi

- Active Directory giriş hataları parola içermeden sunucu ve hata türüyle loglanmaya başladı.
- Windows'ta tam test paketinin kaynak tüketmeden tek seferde tamamlanması sağlandı.
- Kimlik doğrulama, oturum ve kullanıcı yönetimi uçları ayrı bir FastAPI router'ına taşındı.
- Ayar doğrulama ve gizli değer yönetimi uçları ayrı bir FastAPI router'ına taşındı.
- Envanter, cihaz tarama ve WMI/WinRM uçları ayrı bir FastAPI router'ına taşındı.
- Ağ keşfi, topoloji ve tarama zamanlaması uçları ayrı bir FastAPI router'ına taşındı.
- IP çakışması ve subnet kapasitesi uçları ayrı bir FastAPI router'ına taşındı.
- Cihaz config yedekleme ve sürüm farkı uçları ayrı bir FastAPI router'ına taşındı.
- Güvenlik duruşu, firewall ve kontrollü simülasyon uçları ayrı bir FastAPI router'ına taşındı.
- Ping, traceroute, DNS, hız testi ve ağ komutu uçları ayrı bir FastAPI router'ına taşındı.
- Analist korelasyonu, eğilim ve ağ bilgi tabanı uçları ayrı bir FastAPI router'ına taşındı.
- Uygulama giriş noktası inceltildi; SQLite ve rol/yetki yardımcıları ortak çekirdek modüllerine taşındı.
- Çalışma aralıkları, saklama süreleri ve güvenlik eşikleri ortam değişkenleriyle yapılandırılabilir hale getirildi.
- Tek parça tarayıcı kodu, her biri 1.000 satırın altında olan native ES modüllerine ayrıldı.
- SNMP switch port taraması eski PySNMP API'sinin yanında PySNMP 7 asenkron API'sini destekleyecek şekilde güncellendi.
- Arka plan yenilemeleri açık olan sayfaya göre sınırlandırıldı.
- Ölçülmeyen web filtresi ve SIEM özellikleri arayüzde açıkça belirtildi.
- README; dinamik rozetler, gerçek ve anonimleştirilmiş ekran görüntüsü, karşılaştırma tablosu ve mimari diyagramla güncellendi.
- WMI, SSH, SNMP ve derin keşif modülleri Mypy denetimine alındı.

[Henüz yayımlanmadı]: https://github.com/AtakanTas-io/NetMon/compare/v2.5.0...HEAD
[2.5.0]: https://github.com/AtakanTas-io/NetMon/releases/tag/v2.5.0
