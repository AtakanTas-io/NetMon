# NetMon v10 – Final Network Intelligence Scope

NetMon'un ana amacı: bağlı ağdaki cihazları mümkün olduğunca hızlı ve güvenilir biçimde keşfetmek, cihaz kimliğini çoklu kanıtla oluşturmak, yetkili derin envanteri toplamak, SQL'de tarihçeyi korumak ve analiste açıklanabilir görünürlük sağlamaktır.

## Tamamlanan ana katmanlar
- Agentless / çok kaynaklı discovery
- Online / discovered / offline / stale ayrımı
- Vendor bağımsız cihaz sınıflandırması ve güven skoru
- Normalleştirilmiş SQL envanteri
- Donanım / yazılım / interface envanteri
- IP değişikliği ve duplicate önleme
- Değişiklik geçmişi
- Network Health
- Security Exposure (bulgu, otomatik açık iddiası değil)
- Multi-source correlation ve inceleme önceliği
- Security baseline
- LLDP/CDP topoloji kanıtı
- Analiz snapshot/trend altyapısı
- Asset tag / owner / department / location / warranty / notes metadata API
- Analyst raporu
- Geniş Network Bilgi Merkezi
- Cyber Lab / Academy altyapısı

## Güvenlik sınırları
- Discovery yerel/özel ağ kapsamına bağlıdır.
- Yetkisiz cihazlarda zorla derin envanter alınmaz.
- SNMP yalnızca yapılandırılmış/yetkili erişim olduğunda kullanılır.
- Port/servis bulguları tek başına güvenlik açığı ilan edilmez.
- Topoloji kanıtı yoksa fiziksel bağlantı uydurulmaz.
- Admin işlemleri audit log'a yazılır.

## Test
26 passed, 1 skipped.
Skipped test Windows DPAPI/pywin32 gerektiren mevcut testtir ve Linux test ortamında atlanır.
