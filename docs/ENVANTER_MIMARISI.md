# Envanter mimarisi

## Öncelik
1. BT varlık envanteri
2. Ajansız ağ keşfi ve topoloji
3. Yetkili derin envanter
4. Siber güvenlik görünürlüğü ve güvenli Cyber Lab
5. NetMon Academy

## Envanter kimliği
- MAC varsa birincil kimlik olarak kullanılır.
- MAC yoksa bilgisayar adı ve IP, o da yoksa IP parmak izi kullanılır.
- IP değişimi yeni varlık oluşturmaz.
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
Ajansız keşif yalnızca ağdan gözlenebilen verileri toplar.
CPU/RAM/disk/yazılım gibi derin sistem bilgileri yalnızca yetkili WMI/WinRM/SSH/SNMP gibi kanallardan alınır.
Yetki yoksa sistem zorlamaz ve eksik alanları açıkça belirtir.

## API
- `GET /api/inventory/summary`
- `GET /api/inventory/assets`
- `GET /api/academy/modules`

Mevcut cihaz ve yetkili envanter API'leri korunur.

## Arayüz
Ana navigasyon yalnızca ürünün çekirdek alanlarına odaklanır:
- Kontrol Merkezi
- BT Varlık Envanteri
- Ağ Keşfi ve Topoloji
- Güvenlik Görünürlüğü
- Cyber Lab
- NetMon Academy
- Ayarlar
- Yönetim

Ping, traceroute, port taraması ve hız testi gibi yardımcı araçlar ana menü dışında tutulur; API işlevleri kullanılmaya devam eder.
