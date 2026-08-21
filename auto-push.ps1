# auto-push.ps1
Write-Host "GitHub Otomatik Güncelleme Başlatılıyor..." -ForegroundColor Cyan

# Git durumunu kontrol et
$gitStatus = git status --porcelain

if ([string]::IsNullOrWhiteSpace($gitStatus)) {
    Write-Host "Değişiklik bulunamadı. İşlem iptal ediliyor." -ForegroundColor Yellow
    exit
}

# Değişiklikleri ekle
git add .

# Tarih ve saat ile commit mesajı oluştur
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$commitMsg = "Otomatik Güncelleme: $date"

# Commit yap
git commit -m "$commitMsg"

# GitHub (AtakaanShiva) profiline pushla
# Not: Branch adınız 'main' veya 'master' olabilir, duruma göre aşağıyı değiştirin.
Write-Host "Kodlar GitHub'a gönderiliyor..." -ForegroundColor Cyan
git push origin main

Write-Host "Başarıyla AtakaanShiva profiline işlendi!" -ForegroundColor Green