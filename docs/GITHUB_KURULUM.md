# GitHub depo kurulumu

Bu dosyadaki ayarlar GitHub arayüzünden bir kez uygulanır. Depodaki iş akışı dosyaları kontrolleri oluşturur; dal korumasını kendiliğinden etkinleştiremez.

## 1. İş akışlarını ilk kez çalıştırma

1. Değişiklikleri geçici bir dala push edin ve pull request açın.
2. **Actions** sekmesinde şu iş akışlarının göründüğünü doğrulayın:
   - `Test`
   - `Lint`
   - `Security`
3. Test matrisindeki Windows/Ubuntu ve Python 3.11/3.13 işlerinin, `quality` ve `dependencies` işlerinin başarılı olmasını bekleyin.
4. Codecov projesini `AtakanTas-io/NetMon` için etkinleştirin. Test iş akışı OIDC kullanır; `CODECOV_TOKEN` saklamaz.

## 2. Main dalını koruma

GitHub'da **Settings → Branches → Add branch protection rule** yolunu açın ve dal deseni olarak `main` yazın.

Şu seçenekleri etkinleştirin:

- **Require a pull request before merging**
- Ekipte birden fazla geliştirici varsa **Required approvals: 1**
- **Dismiss stale pull request approvals when new commits are pushed**
- **Require status checks to pass before merging**
- **Require branches to be up to date before merging**
- **Do not allow bypassing the above settings**
- Yöneticiler için de kuralın uygulanması
- Force push ve dal silme yasağı

Zorunlu status check listesine ilk başarılı PR çalışmasından sonra şunları ekleyin:

- Windows ve Ubuntu için Python 3.11/3.13 test işleri
- `quality` (Ruff, format ve Mypy)
- `dependencies` (pip-audit ve Bandit)

GitHub arayüzündeki adlar iş akışı/job adlarından türetilir; listede görünen tam adları seçin.

Tek geliştiricili depoda kendi PR'ınızı onaylamaya çalışmayın. GitHub bunu bağımsız onay saymaz. Bu durumda required approval değerini `0` bırakın; PR zorunluluğu, güncel dal şartı ve tüm CI kontrollerini zorunlu tutun. İkinci bir bakımcı eklendiğinde değeri `1` yapın.

## 3. Merge ve sürüm politikası

- Tercih edilen merge yöntemini **Squash merging** olarak açın.
- Commit mesajlarını kısa, doğal ve Türkçe tutun; `feat:`/`fix:` gibi ön ekler kullanmayın.
- Sürüm öncesinde tam test, Ruff, Mypy, Bandit ve `pip-audit` sonuçlarını kontrol edin.
- Hazır commit üzerinde imzalı veya açıklamalı bir `v*` etiketi oluşturun ve push edin.
- `Windows sürümü` iş akışının `NetMon.exe` ve `NetMon.exe.sha256` ekleriyle GitHub Release oluşturduğunu doğrulayın.

Örnek yerel etiket komutları:

```bash
git tag -a v2.5.0 -m "NetMon 2.5.0"
git push origin v2.5.0
```

Etiketi yalnızca aynı sürüm başlığı `CHANGELOG.md` içinde yer aldığında oluşturun. Yayımlanmış bir etiketi farklı commit'e taşımayın; düzeltme gerekiyorsa yeni bir patch sürümü çıkarın.

## 4. Depo ayarları kontrol listesi

- [ ] Issues açık
- [ ] Actions için **Read and write permissions** yalnızca release iş akışının ihtiyaç duyduğu `contents: write` izniyle sınırlandırılmış
- [ ] Dependabot alerts ve Dependabot security updates açık
- [ ] Private vulnerability reporting açık
- [ ] Secret scanning ve push protection, plan destekliyorsa açık
- [ ] `main` doğrudan push, force push ve silmeye kapalı
- [ ] Pull request şablonundaki test ve platform alanları dolduruluyor
- [ ] Sürüm eki indirildikten sonra SHA256 değeri doğrulanıyor
