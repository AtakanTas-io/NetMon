# NetMon Güncelleme Raporu (2026-08-27)

## Teslimat özeti

Bu sürüm, kontrol merkezinin ölçülmeyen veriyi gerçekmiş gibi göstermemesi ve operatörün sistem durumunu tek bakışta doğrulayabilmesi için tamamlandı. Arayüz ile API sözleşmeleri birlikte güncellendi; ayarlar kalıcı hale getirildi ve kritik işlevlerin çalışma durumu görünür kılındı.

## Tamamlanan geliştirmeler

- Canlı trafik ekranında kapsam, ölçüm kaynağı, veri yaşı ve hata durumu açıkça gösteriliyor.
- Arka plan yenilemeleri aktif sayfaya göre sınırlandırıldı; gereksiz istekler azaltıldı.
- `/api/system/readiness` ile veritabanı, DHCP izleyici, trafik ölçümü, AD, web filtresi ve SIEM yetenekleri `ready`, `warning`, `error` veya `unavailable` olarak raporlanıyor.
- DHCP izleyicisinin çalışma ve hata durumu API katmanına taşındı; yetkili DHCP sunucuları kalıcı ayarlardan okunuyor.
- Active Directory ve yetkili DHCP ayarlarında doğrulama, normalizasyon ve kalıcılık sağlandı.
- Cihaz sahibi bilgisi veritabanına ve canlı önbelleğe birlikte yazılıyor.
- Güvenlik duruşu ekranında ölçülmeyen web filtresi/SIEM özellikleri açıkça “kullanılamıyor” olarak belirtiliyor.
- Yer tutucu ve simülasyon mesajları gerçek API işlemleri ve görünür hata bildirimleriyle değiştirildi.
- Operasyon raporu, lokasyon atama ve erişim yetenekleri için ek sözleşme testleri eklendi.

## Dosya ve klasör düzeni

- Uygulama kodu `backend/` ve `frontend/`, testler `tests/`, yardımcı komutlar `scripts/`, raporlar `docs/` altında tutuluyor.
- Kökteki `build.bat`, `calistir.bat` ve `auto-push.ps1` dosyaları geriye uyumlu kısa yönlendiricilerdir; gerçek komutlar `scripts/windows/` altındadır.
- `.pytest-*` çalışma klasörleri sürüm kontrolü dışında bırakıldı. SQLite çalışma verileri, parolalar, günlükler ve derleme çıktıları da `.gitignore` ile korunuyor.

## Kalite sonucu

- Python sözdizimi/bytecode doğrulaması: başarılı
- JavaScript sözdizimi doğrulaması: başarılı
- Pytest: **105 passed**
- Git whitespace denetimi: başarılı

Bu rapordaki test sayısı, teslimat öncesindeki tam yerel test koşusunun sonucudur.
