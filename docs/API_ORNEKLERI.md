# NetMon API örnekleri

API, kullanıcı oturumu veya `nm_` ile başlayan API anahtarı üzerinden `Bearer` kimlik doğrulaması kullanır. Aşağıdaki değerler örnektir; gerçek parola veya anahtarı kaynak koduna yazmayın.

## Kullanıcı oturumu açma

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"PAROLANIZ"}'
```

Yanıttaki `token` değeri korumalı çağrılarda kullanılır:

```bash
curl http://127.0.0.1:8000/api/history?range=24h \
  -H "Authorization: Bearer OTURUM_TOKENI"
```

## NOC görünürlük özeti

Gecikme, jitter ve paket kaybı trendini; güvenlik skorunu; 30 gün içinde sona erecek sertifikaları ve DHCP izleyici durumunu tek yanıtta verir. Desteklenen zaman aralıkları `1h`, `24h` ve `7d` değerleridir.

```bash
curl "http://127.0.0.1:8000/api/visibility/summary?range=24h" \
  -H "Authorization: Bearer OTURUM_TOKENI"
```

Gecikme ve kayıp değerleri periyodik ICMP tanı snapshot'larından gelir. DHCP lease kaynağı bağlı değilse havuz doluluğu üretilmez; IPAM ekranındaki oran yalnız keşifte gözlenen adres kullanımını ifade eder.

## Faz 3 güvence taramaları

Servis banner'larındaki ürün ve sürüm kanıtını yerel, NVD doğrulamalı başlangıç kataloğuyla eşleştirmek için:

```bash
curl -X POST http://127.0.0.1:8000/api/security/cve-scan \
  -H "Authorization: Bearer OTURUM_TOKENI"
```

Bu uç canlı NVD akışı veya tam zafiyet tarayıcısı değildir. Yalnız kesin ürün+sürüm kanıtı bulunan kuralları raporlar; açık port tek başına CVE sayılmaz.

Yetkili yerel cihazlarda `public`/`private` varsayılan SNMP community denetimi açık onay ister:

```bash
curl -X POST http://127.0.0.1:8000/api/security/credential-audit \
  -H "Authorization: Bearer OTURUM_TOKENI" \
  -H "Content-Type: application/json" \
  -d '{"targets":["10.0.0.10"],"acknowledge_authorized":true}'
```

İşletim sisteminin mevcut ARP/komşu önbelleğini trafik üretmeden okumak için:

```bash
curl -X POST http://127.0.0.1:8000/api/discovery/passive-snapshot \
  -H "Authorization: Bearer OTURUM_TOKENI"
```

Hassas bir IP veya CIDR'yi aktif keşif, Nmap ve varsayılan kimlik denetiminden çıkarmak için `POST /api/discovery/exemptions` kullanılır. Kayıtlı NCM konfigürasyonunu temel çizgiyle karşılaştırmak için `POST /api/ncm/compliance` çağrılır:

```json
{"ip":"10.0.0.30","config_id":42,"baseline_id":"network_device_level1"}
```

## Gelişmiş ağ araması

`GET /api/search` keşif, normalleştirilmiş envanter, yazılım, sertifika, son CVE korelasyonu ve NCM konfigürasyon metaverisini tek `search_documents` indeksinde birleştirir.

```bash
curl --get http://127.0.0.1:8000/api/search \
  -H "Authorization: Bearer OTURUM_TOKENI" \
  --data-urlencode 'q=ip:10.0.1.0/24 AND type:switch AND NOT status:offline' \
  --data 'page=1&page_size=25&sort=last_seen&order=desc'
```

Desteklenen alanlar arasında `ip`, `mac`, `hostname`, `type`, `vendor`, `status`, `last_seen`, `port`, `vlan`, `subnet`, `site`, `switch_port`, `os`, `software`, `service`, `banner`, `cve`, `cert`, `config`, `config_changed`, `latency`, `loss`, `uptime` ve `verified` bulunur. IP alanı tek adres, kısa aralık (`10.0.0.1-50`) veya CIDR kabul eder. Sayısal alanlarda `>`, `>=`, `<`, `<=`; mantıksal ifadelerde `AND`, `OR`, `NOT` ve parantez kullanılabilir.

Regex yalnız alan bazında kullanılır ve kötüye kullanım korumaları uygulanır:

```text
hostname:/^SW-CORE-\d{2}$/ AND config:"access-list 101"
```

Kullanıcıya özel aramalar `GET/POST /api/search/saved` ile yönetilir. Sonuçlar `GET /api/search/export?format=csv` veya `format=json` üzerinden dışa aktarılabilir.

## Site tanımlama

`locations.manage` izni gerekir. Yalnızca `/16` veya daha dar özel IPv4 ağları kabul edilir; etkin sitelerin subnetleri çakışamaz.

```bash
curl -X POST http://127.0.0.1:8000/api/sites \
  -H "Authorization: Bearer OTURUM_TOKENI" \
  -H "Content-Type: application/json" \
  -d '{"name":"İstanbul Merkez","description":"Ana ofis","cidrs":["10.20.0.0/16"]}'
```

## Alarm kuralı tanımlama

Desteklenen türler: `offline_duration`, `new_device`, `rogue_dhcp`, `ip_conflict` ve `config_diff`.

```bash
curl -X POST http://127.0.0.1:8000/api/alert-rules \
  -H "Authorization: Bearer OTURUM_TOKENI" \
  -H "Content-Type: application/json" \
  -d '{"name":"Kritik cihaz çevrimdışı","rule_type":"offline_duration","threshold_seconds":1800,"level":"critical","channels":["email","webhook"],"cooldown_seconds":3600}'
```

Kurallar arka planda dakikada bir değerlendirilir. Elle değerlendirmek için:

```bash
curl -X POST http://127.0.0.1:8000/api/alert-rules/evaluate \
  -H "Authorization: Bearer OTURUM_TOKENI"
```

## Geçmiş ve raporlar

```bash
curl "http://127.0.0.1:8000/api/history?range=30d&site_id=1" \
  -H "Authorization: Bearer OTURUM_TOKENI"

curl "http://127.0.0.1:8000/api/reports/export?format=xlsx&site_id=1" \
  -H "Authorization: Bearer OTURUM_TOKENI" \
  --output netmon-report.xlsx
```

Zamanlanmış rapor, alıcı boş bırakılırsa yalnızca üretilir; alıcı girilirse Ayarlar ekranındaki SMTP yapılandırmasıyla gönderilir.

```bash
curl -X POST http://127.0.0.1:8000/api/report-schedules \
  -H "Authorization: Bearer OTURUM_TOKENI" \
  -H "Content-Type: application/json" \
  -d '{"name":"Haftalık NOC raporu","format":"pdf","interval_seconds":604800,"recipient":"noc@example.com","site_id":1}'
```

## Sınırlı API anahtarı

Anahtar, kullanıcının rolünden daha geniş izin alamaz. Ham anahtar yalnız oluşturma yanıtında bir kez gösterilir.

```bash
curl -X POST http://127.0.0.1:8000/api/api-keys \
  -H "Authorization: Bearer OTURUM_TOKENI" \
  -H "Content-Type: application/json" \
  -d '{"name":"Rapor otomasyonu","permissions":["reports.view"],"expires_in_days":365,"rate_limit_per_minute":60}'
```

Oluşan anahtarı kullanma:

```bash
curl http://127.0.0.1:8000/api/history?range=7d \
  -H "Authorization: Bearer nm_ORNEK_ANAHTAR"
```

Anahtarı iptal etmek için anahtarı oluşturan kullanıcının oturum tokenı gerekir:

```bash
curl -X DELETE http://127.0.0.1:8000/api/api-keys/1 \
  -H "Authorization: Bearer OTURUM_TOKENI"
```
