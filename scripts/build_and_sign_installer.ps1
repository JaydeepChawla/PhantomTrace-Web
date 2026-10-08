<#
.SYNOPSIS
    Build and Authenticode Sign PhantomTrace Windows Installer (PhantomTrace_Agent_Setup.exe)
.DESCRIPTION
    1. Compiles the standalone installer using Inno Setup Compiler (ISCC.exe)
    2. Signs PhantomTrace_Agent_Setup.exe with Authenticode SHA-256 and RFC 3161 timestamping
    3. Verifies the signature
    4. Syncs the signed installer to public/ and public/downloads/
#>

[CmdletBinding()]
param(
    [string]$Thumbprint = "24BCEC7C3267546BB34F791B49BDC053FBD6ED05",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$InstallerIss = Join-Path $RootDir "installer\PhantomTrace_Agent_Setup.iss"
$DistInstaller = Join-Path $RootDir "dist\PhantomTrace_Agent_Setup.exe"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE — BUILD & SIGN INSTALLER PIPELINE" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Locate Inno Setup Compiler (ISCC.exe)
$IsccCandidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)

$IsccExe = $null
foreach ($cand in $IsccCandidates) {
    if (Test-Path $cand) {
        $IsccExe = $cand
        break
    }
}

if (-not $IsccExe) {
    $found = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($found) { $IsccExe = $found.Source }
}

if (-not $IsccExe) {
    Write-Error "Inno Setup Compiler (ISCC.exe) not found."
    exit 1
}

Write-Host "[1/4] Found Inno Setup Compiler: $IsccExe" -ForegroundColor Green

# 2. Compile Installer
Write-Host "[2/4] Compiling PhantomTrace_Agent_Setup.exe..." -ForegroundColor Cyan
Push-Location (Join-Path $RootDir "installer")
try {
    & $IsccExe $InstallerIss
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Inno Setup compilation failed with exit code $LASTEXITCODE."
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path $DistInstaller)) {
    Write-Error "Installer executable not found at $DistInstaller after compilation."
    exit 1
}

$installerSize = (Get-Item $DistInstaller).Length
Write-Host "      Compiled successfully: $DistInstaller ($installerSize bytes)" -ForegroundColor Green

# 3. Authenticode Sign Installer
Write-Host "[3/4] Signing installer with certificate $Thumbprint..." -ForegroundColor Cyan

$Cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
if (-not $Cert) {
    $Cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
}

if (-not $Cert) {
    Write-Error "Signing certificate with thumbprint $Thumbprint not found in store."
    exit 1
}

$sigResult = Set-AuthenticodeSignature -FilePath $DistInstaller -Certificate $Cert -HashAlgorithm "SHA256" -TimestampServer $TimestampUrl
if ($sigResult.Status -ne "Valid") {
    Write-Error "Installer signing failed. Status: $($sigResult.Status) - $($sigResult.StatusMessage)"
    exit 1
}

Write-Host "      Installer signed successfully: $($sigResult.SignerCertificate.Subject)" -ForegroundColor Green

# 4. Sync signed installer to deployment targets
Write-Host "[4/4] Synchronizing signed installer to web distribution directories..." -ForegroundColor Cyan

$targets = @(
    (Join-Path $RootDir "public\PhantomTrace_Agent_Setup.exe"),
    (Join-Path $RootDir "public\downloads\PhantomTrace_Agent_Setup.exe"),
    (Join-Path $RootDir "dist\downloads\PhantomTrace_Agent_Setup.exe")
)

foreach ($target in $targets) {
    $targetDir = Split-Path $target
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    Copy-Item -Path $DistInstaller -Destination $target -Force
    Write-Host "      Synced -> $target" -ForegroundColor Gray
}

Write-Host "====================================================" -ForegroundColor Green
Write-Host " INSTALLER PIPELINE COMPLETE — PRODUCTION READY" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
