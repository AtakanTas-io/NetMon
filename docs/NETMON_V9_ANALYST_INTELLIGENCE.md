# NetMon v9 — Network Analyst Intelligence

## Amaç
NetMon; vendor bağımsız ağ keşfi, BT varlık envanteri, güvenlik görünürlüğü ve eğitim işlevlerini tek üründe birleştirir.

## Analist katmanı
- `/api/analyst/summary`: ağ sağlığı, envanter tamlığı, güvenlik incelemeleri ve performans özeti.
- `/api/analyst/devices`: cihaz bazında kimlik, sınıf güveni, kanıt, maruziyet ve öneriler.
- `/api/analyst/device/{ip}`: tek cihaz analizi.
- `/api/analyst/anomalies`: envanter değişiklikleri; saldırı iddiası üretmez.
- `/api/analyst/exposure`: açık/erişilebilir servislerden savunma amaçlı inceleme sinyalleri.
- `/api/knowledge/network`: keşif ve güvenlik kavramları için açıklamalar.

## Güvenlik ilkesi
NetMon cihaz yapılandırmasını değiştirmez. SNMP/LLDP/CDP gibi kaynaklar yalnızca yetkili salt-okuma görünürlük için kullanılır. Açık port tek başına güvenlik açığı olarak raporlanmaz.

## Test
`PYTHONPATH=. pytest -q` → 25 passed, 1 skipped (Windows DPAPI testi Windows ortamına özgü).
`node --check frontend/app.js` → PASS.
`python -m py_compile backend/server.py` → PASS.
