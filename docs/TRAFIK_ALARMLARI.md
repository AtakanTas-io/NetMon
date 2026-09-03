# Trafik alarm kuralları

Güvenlik sayfasındaki Alarm Kuralı penceresinde iki trafik türü bulunur.
Mevcut beş kuralın değerlendirmesi, bildirim kanalları ve tekrar bekleme süresi değişmez.

## Bant genişliği sıçraması

`bandwidth_spike`, `traffic` tablosundaki Wi-Fi ve Ethernet gönderme/alma hızlarını
toplar. Değerler bit/saniyedir. Son pencere içindeki en son ölçüm, hemen önceki
eşit uzunluktaki pencerenin ölçüm ortalamasından büyük bir sıçrama yaparsa alarm üretir.

`threshold_seconds` pencere uzunluğudur; 0 verilirse 300 saniye kullanılır.
`target` çarpandır: örneğin `3x` veya `4.5x`. Boş, geçersiz, 1'den büyük olmayan
veya 1000'i aşan değerler 3x olarak yorumlanır. Eşiğe eşit değer alarm üretmez.
Önceki pencerede pozitif ölçülmüş bir ortalama yoksa tahmini bir referans üretilmez.
Zaman aralıkları `(şimdi−2×pencere, şimdi−pencere]` ve `(şimdi−pencere, şimdi]` olarak ayrılır.
En son ölçüm zaten değerlendirilmişse, yeni ölçüm gelmeden tekrar alarm üretilmez.

## Bağlantı patlaması

`connection_burst`, `connections.first_seen` kayıtlarını uygulama adına göre gruplar.
Pencere içinde **20'den fazla farklı uzak IP** ilk kez görüldüğünde alarm üretir.
Bu sabit eşik bir geçmiş ortalaması değildir; alarm mesajında açıkça eşik olarak gösterilir.
`threshold_seconds` burada da pencere uzunluğudur; 0 verilirse 300 saniye kullanılır.
`target` bu türde kullanılmaz.

Aynı IP'ye farklı portlardan açılan bağlantılar bir kez sayılır. Kapalı bağlantılar
ilk görülme zamanları penceredeyse sayılır. Farklı uygulamalar ayrı değerlendirilir.
Önceki değerlendirmelerde biriken kayıtlar pencere toplamını korur; ancak aynı
pencerede zaten geçilmiş eşik, yeni birkaç kayıt geldiği için tekrar alarm üretmez.
Pencere kaydıkça sayı eşiğin altına indikten sonra yeni bir eşik geçişi değerlendirilebilir.
Gelecek zamanlı kayıtlar ve uygulama adı/uzak IP'si olmayan kayıtlar sayılmaz.

Her iki tür de mevcut `cooldown_seconds` kuralına tabidir. Sonuçlar `alert_events`
ve alarm gelen kutusunda kanıtlarıyla saklanır; mevcut canlı alarm akışını kullanır.
