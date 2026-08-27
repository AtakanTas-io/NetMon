# Katkıda bulunma

Hata bildirirken işletim sistemi, Python sürümü, tekrar adımları ve varsa ilgili log satırlarını ekleyin. Parola, token, kullanıcı adı veya şirket ağına ait gerçek IP adreslerini paylaşmayın.

Kod değişikliği göndermek için:

1. Depoyu fork edin ve ayrı bir dal açın.
2. Değişikliği tek bir konu ile sınırlı tutun.
3. İlgili testi ekleyin veya mevcut testi güncelleyin.
4. `python -m pytest tests -v` komutunu çalıştırın.
5. Pull request açıklamasında neyi, neden değiştirdiğinizi ve nasıl denediğinizi yazın.

## Commit mesajları

Kısa ve doğal Türkçe kullanın. Conventional Commit ön ekleri zorunlu değildir ve bu depoda tercih edilmez.

Örnekler:

- `DHCP ayarını veritabanına kaydet`
- `Boş trafik verisinde hata mesajını göster`
- `Switch port eşleştirmesi için test ekle`

Backend, frontend, test ve belge değişikliklerini mümkün olduğunda ayrı commitlerde tutun. `git add .` yerine ilgili dosyaları açıkça stage edin.
