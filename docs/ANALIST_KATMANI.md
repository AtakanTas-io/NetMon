# Analist katmanı

## Amaç
Bu bölüm ağ keşfi ve envanter kayıtlarını cihaz bazında özetler.

## API'ler
- `/api/analyst/summary`: ağ sağlığı, envanter tamlığı, güvenlik incelemeleri ve performans özeti.
- `/api/analyst/devices`: cihaz bazında kimlik, sınıf güveni, kanıt, maruziyet ve öneriler.
- `/api/analyst/device/{ip}`: tek cihaz analizi.
- `/api/analyst/anomalies`: envanter değişiklikleri; saldırı iddiası üretmez.
- `/api/analyst/exposure`: açık/erişilebilir servislerden savunma amaçlı inceleme sinyalleri.
- `/api/knowledge/network`: keşif ve güvenlik kavramları için açıklamalar.

## Güvenlik ilkesi
NetMon cihaz yapılandırmasını değiştirmez. SNMP/LLDP/CDP gibi kaynaklar yalnızca yetkili salt-okuma görünürlük için kullanılır. Açık port tek başına güvenlik açığı olarak raporlanmaz.
