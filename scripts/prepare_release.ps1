Param(
    [switch]$CheckOnly = $false,
    [string]$OutDir = "dist",
    [string]$Features = "api_std_http,sign_hmac,sign_host"
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
    param([string]$Title, [scriptblock]$Action, [switch]$Optional = $false)
    Write-Host "==> $Title"
    try { & $Action }
    catch {
        if ($Optional) {
            Write-Warning "Skipped optional step: $Title ($($_.Exception.Message))"
        } else {
            throw
        }
    }
}

function Has-Cmd {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# 1) Quality & security gates (local)
Invoke-Step "cargo fmt --check"      { cargo fmt --check }
Invoke-Step "cargo clippy -D warnings" { cargo clippy -q -D warnings --all-targets --all-features }
Invoke-Step "cargo test --lib ($Features)" { cargo test -q --features $Features --lib }

if (Has-Cmd "cargo-audit") {
    Invoke-Step "cargo audit" { cargo audit -q } -Optional
} elseif (Has-Cmd "cargo") {
    Invoke-Step "cargo audit (cargo-install required)" { cargo audit -q } -Optional
}

if (Has-Cmd "cargo-deny") {
    Invoke-Step "cargo deny check" { cargo deny check -q } -Optional
}

if ($CheckOnly) {
    Write-Host "Checks completed. Exiting due to -CheckOnly."
    exit 0
}

# 2) Create clean release archive (whitelist copy)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Resolve-Path (Join-Path $root ".."))

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stage = Join-Path $OutDir "stage"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

$include = @(
    "Cargo.toml",
    "Cargo.lock",
    "LICENSE",
    "README.md",
    "README_AR.md",
    "include",
    "src"
)

foreach ($p in $include) {
    if (Test-Path $p) {
        Write-Host "Copying $p"
        Copy-Item $p -Recurse -Force -Destination (Join-Path $stage $p)
    } else {
        Write-Warning "Missing path (skipped): $p"
    }
}

$zip = Join-Path $OutDir "MKT-KSA-Geolocation-Security-clean.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -Force

# 3) Summaries
$sum = Get-ChildItem -Recurse $stage -File | Measure-Object -Property Length -Sum
$sizeMB = [Math]::Round(($sum.Sum / 1MB), 2)
$filesCount = (Get-ChildItem -Recurse $stage -File).Count

Write-Host "Clean archive created: $zip"
Write-Host "Files: $filesCount | Size: $sizeMB MB"

# 4) Capture the list produced by cargo package for a final verification
Invoke-Step "cargo package --list (verification)" {
    cargo package --allow-dirty --list | Out-File -FilePath (Join-Path $OutDir "cargo_package_list.txt") -Encoding UTF8
} -Optional

Write-Host "Done."


