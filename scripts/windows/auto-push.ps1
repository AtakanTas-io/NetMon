# auto-push.ps1
Write-Host "GitHub gönderimi başlatılıyor..." -ForegroundColor Cyan

# Git durumunu kontrol et
$gitStatus = git status --porcelain

if (-not [string]::IsNullOrWhiteSpace($gitStatus)) {
    Write-Host "Commit edilmemiş değişiklikler var." -ForegroundColor Yellow
    Write-Host "Backend, frontend, test ve dokümantasyon değişikliklerini ayrı ayrı stage edip commit edin." -ForegroundColor Yellow
    Write-Host "Bu araç toplu 'git add .' veya otomatik commit yapmaz." -ForegroundColor Yellow
    exit 1
}

$branch = (git branch --show-current).Trim()
if ([string]::IsNullOrWhiteSpace($branch)) {
    Write-Host "Aktif Git dalı belirlenemedi." -ForegroundColor Red
    exit 1
}

Write-Host "$branch dalındaki hazır commitler GitHub'a gönderiliyor..." -ForegroundColor Cyan
git push origin $branch
if ($LASTEXITCODE -ne 0) {
    Write-Host "GitHub gönderimi başarısız oldu." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Gönderim tamamlandı." -ForegroundColor Green
