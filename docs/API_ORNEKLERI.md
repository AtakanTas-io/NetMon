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
