# Değişiklikler

## Henüz yayımlanmadı

- Windows dışındaki sistemlerde gizli ayarlar için Fernet tabanlı yerel şifreleme eklendi.
- Desteklenen işletim sistemi ve özellik gereksinimleri README'de açıklandı.
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
- WMI, DHCP, SNMP switch eşleme ve derin keşif motorları için hata yolu testleri ile yüzde 70 coverage kapısı eklendi.
- Trafik ekranına ölçüm kaynağı ve veri yaşı eklendi.
- Sistem bileşenlerinin hazırlık durumunu döndüren API eklendi.
- DHCP ve Active Directory ayarları kalıcı hale getirildi.
- Cihaz sahibi bilgisi envantere kaydedildi.
- Arka plan yenilemeleri açık olan sayfaya göre sınırlandırıldı.
- Ölçülmeyen web filtresi ve SIEM özellikleri arayüzde açıkça belirtildi.
- Operasyon ve ayar akışları için yeni testler eklendi.

Sürüm numarası verildiğinde bu bölüm ilgili sürüm başlığına taşınacak.
