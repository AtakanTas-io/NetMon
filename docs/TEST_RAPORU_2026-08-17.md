# NetMon Test Raporu – 2026-08-17

## Yapılan değişiklikler
- Normalize edilmiş SQL asset inventory çekirdeği eklendi.
- Agentless Discovery sonuçlarının SQL asset tablosuna yazılması eklendi.
- Yetkili WMI/WinRM sonuçları normalize inventory ile eşlendi.
- IP değişimlerinde stabil identity yaklaşımı uygulandı.
- Inventory summary/assets API'leri eklendi.
- Academy module API eklendi.
- Ana navigasyon envanter/ağ/güvenlik/eğitim odaklı sadeleştirildi.
- Yardımcı network araçları ana navigasyondan çıkarıldı; backend geriye dönük uyumluluk için bırakıldı.
- SQLite eşzamanlı yazımında yeni normalize inventory bağlantısının kilitlenmemesi için transaction sınırı düzeltildi.

## Testler
Çalıştırılan komut:
`pytest -q tests/test_inventory_engines.py tests/test_server_security.py -k 'not management_secret_is_encrypted_and_never_returned'`

Sonuç:
- 13 passed
- 1 deselected

Deselect edilen test Linux test ortamında Windows DPAPI beklediği için çalıştırılmadı. Bu test Windows üzerinde mevcut güvenlik davranışını doğrulamak içindir.

## Kalan işler
- Windows gerçek ortamında WMI/WinRM inventory uçtan uca test edilmeli.
- Gerçek şirket subnet'i üzerinde agentless discovery doğrulanmalı.
- SNMP/SSH adapterlarının normalize interface/software kayıtları genişletilmeli.
- Cyber Lab senaryoları güvenli sandbox içinde ayrı ayrı test edilmeli.
- Frontend için Playwright/E2E testleri eklenmeli.
