# NetMon – Envanter Odaklı Ürün Mimarisi

## Öncelik
1. BT varlık envanteri
2. Agentless ağ keşfi ve topoloji
3. Yetkili derin envanter
4. Siber güvenlik görünürlüğü ve güvenli Cyber Lab
5. NetMon Academy

## Envanter kimliği
- MAC varsa birincil kimlik olarak kullanılır.
- MAC yoksa hostname + IP, o da yoksa IP fingerprint kullanılır.
- IP değişimi yeni asset oluşturmaz.
- Eksik bilgi uydurulmaz; NULL/UNKNOWN kullanılır.

## SQL
Yeni normalize tablolar:
- `inventory_assets`
- `inventory_hardware`
- `inventory_interfaces`
- `inventory_software`
- `inventory_scan_runs`

Mevcut `known_devices` ve `device_inventory` geriye dönük uyumluluk için korunur.

## Yetki modeli
Agentless Discovery yalnızca ağdan teknik olarak gözlenebilen verileri toplar.
CPU/RAM/disk/yazılım gibi derin sistem bilgileri yalnızca yetkili WMI/WinRM/SSH/SNMP gibi kanallardan alınır.
Yetki yoksa sistem zorlamaz ve eksik alanları açıkça belirtir.

## API
- `GET /api/inventory/summary`
- `GET /api/inventory/assets`
- `GET /api/academy/modules`

Mevcut cihaz ve yetkili inventory API'leri korunmuştur.

## UI sadeleştirmesi
Ana navigasyon yalnızca ürünün çekirdek alanlarına odaklanır:
- Kontrol Merkezi
- BT Varlık Envanteri
- Ağ Keşfi ve Topoloji
- Güvenlik Görünürlüğü
- Cyber Lab
- NetMon Academy
- Ayarlar
- Yönetim

Ping, traceroute, portscan ve speedtest gibi yardımcı araçlar ana navigasyondan çıkarılmış; backend fonksiyonları gereksiz yere silinmemiştir.
