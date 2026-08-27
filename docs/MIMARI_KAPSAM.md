# Mimari kapsam

NetMon ağdaki cihazları keşfeder, gözlemleri envantere yazar ve yetkili erişim varsa ayrıntılı sistem bilgilerini toplar.

## Mevcut yapılar
- Ajansız, çok kaynaklı keşif
- Çevrimiçi, keşfedilmiş, çevrimdışı ve eski kayıt ayrımı
- Üreticiden bağımsız cihaz sınıflandırması ve güven skoru
- Normalleştirilmiş SQL envanteri
- Donanım, yazılım ve ağ arayüzü envanteri
- IP değişikliği takibi ve tekrar kayıt önleme
- Değişiklik geçmişi
- Ağ sağlığı özeti
- Açık servis bulguları
- Birden fazla kaynaktan gelen gözlemlerin eşleştirilmesi
- Güvenlik temel kontrolleri
- LLDP/CDP topoloji kanıtı
- Analiz geçmişi
- Etiket, sahip, bölüm, konum, garanti ve not alanları
- Analist raporu ve ağ bilgi merkezi

## Güvenlik sınırları
- Discovery yerel/özel ağ kapsamına bağlıdır.
- Yetkisiz cihazlarda zorla derin envanter alınmaz.
- SNMP yalnızca yapılandırılmış/yetkili erişim olduğunda kullanılır.
- Port/servis bulguları tek başına güvenlik açığı ilan edilmez.
- Topoloji kanıtı yoksa fiziksel bağlantı uydurulmaz.
- Yönetici işlemleri kayıt altına alınır.
