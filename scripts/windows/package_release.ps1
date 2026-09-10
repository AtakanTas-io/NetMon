param(
    [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "../..")).Path
if (-not $OutputPath) {
    $OutputPath = Join-Path $projectRoot ("dist/NetMon-source-{0}.zip" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$archivePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

function Test-ExcludedName {
    param([string]$Name)
    foreach ($pattern in @(
        ".buildenv", ".git", ".coverage*", "__pycache__", "build", "dist", "pytest_temp*",
        ".venv", "venv", "env", ".pytest_cache", ".cache", ".env*", "netmon.db*", "*.db*",
        "initial_admin_password.txt", "*.key", "*.pem", "*.pfx", "*.pyc", "*.pyo", "*.log", "*.exe", "*.dll"
    )) {
        if ($Name -like $pattern) { return $true }
    }
    return $false
}

function Get-PackageFiles {
    param([System.IO.DirectoryInfo]$Directory)
    # Baglantilari izleme; izin verilen agacin disindaki dosyalari pakete alma.
    if ($Directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return }
    foreach ($item in Get-ChildItem -LiteralPath $Directory.FullName -Force) {
        if (Test-ExcludedName $item.Name) { continue }
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
        if ($item.PSIsContainer) {
            Get-PackageFiles $item
        } else {
            $item
        }
    }
}

$packageFiles = @(
    foreach ($name in @(".github", "assets", "backend", "frontend", "tests", "docs", "scripts")) {
        $directory = Join-Path $projectRoot $name
        if (Test-Path -LiteralPath $directory -PathType Container) {
            Get-PackageFiles (Get-Item -LiteralPath $directory)
        }
    }
    foreach ($name in @(
        ".env.example", ".gitattributes", ".gitignore", "pyproject.toml", "pytest.ini",
        "requirements.txt", "requirements-dev.txt", "README.md", "CHANGELOG.md",
        "CONTRIBUTING.md", "SECURITY.md", "ROADMAP.md", "LICENSE", "LICENSE.md", "LICENSE.txt"
    )) {
        $document = Join-Path $projectRoot $name
        if (Test-Path -LiteralPath $document -PathType Leaf) {
            $item = Get-Item -LiteralPath $document
            if (-not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { $item }
        }
    }
)

New-Item -ItemType Directory -Path (Split-Path -Parent $archivePath) -Force | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
# Create modu mevcut ZIP dosyasinin uzerine yazmaz.
$archive = [System.IO.Compression.ZipFile]::Open($archivePath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in $packageFiles | Sort-Object FullName) {
        $relativePath = $file.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $archive, $file.FullName, $relativePath, [System.IO.Compression.CompressionLevel]::Optimal
        ) | Out-Null
    }
} finally {
    $archive.Dispose()
}
Write-Output "Paket olusturuldu: $archivePath"
