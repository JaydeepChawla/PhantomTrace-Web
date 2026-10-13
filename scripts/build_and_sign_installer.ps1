<#
.SYNOPSIS
    Build PhantomTrace Windows Installer (PhantomTrace_Agent_Setup.exe) - Unsigned Release
.DESCRIPTION
    1. Locates Inno Setup Compiler (ISCC.exe) across standard search paths
    2. Verifies and stages required binaries (background agent and scanner CLI)
    3. Compiles the standalone installer using Inno Setup Compiler
    4. Calculates SHA-256 checksum from the exact compiled installer on disk
    5. Generates standard checksum manifest (.sha256) and release metadata (.json)
    6. Keeps build artifacts strictly isolated in dist/ without overwriting public website files
#>

[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [string]$ScannerDir = "",
    [switch]$SkipSigningIfUnconfigured = $false, # Retained for compatibility
    [switch]$AllowDevSelfSigned = $false,        # Retained for compatibility
    [string]$TimestampUrl = "",                  # Retained for compatibility
    [string]$ExpectedPublisher = ""              # Retained for compatibility
)

$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$InstallerIss = Join-Path $RootDir "installer\PhantomTrace_Agent_Setup.iss"
$DistDir = Join-Path $RootDir "dist"
$DistInstaller = Join-Path $DistDir "PhantomTrace_Agent_Setup.exe"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE - BUILD INSTALLER PIPELINE (UNSIGNED)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. LOCATE INNO SETUP COMPILER (ISCC.exe)
# ----------------------------------------------------
$IsccCandidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)

$IsccExe = $null
foreach ($cand in $IsccCandidates) {
    if ($cand -and (Test-Path $cand)) {
        $IsccExe = $cand
        break
    }
}

if (-not $IsccExe) {
    $found = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($found) { $IsccExe = $found.Source }
}

if (-not $IsccExe) {
    Write-Error "Inno Setup Compiler (ISCC.exe) not found. Please install Inno Setup 6 or add ISCC.exe to PATH."
    exit 1
}

Write-Host "[1/4] Found Inno Setup Compiler: $IsccExe" -ForegroundColor Green

# ----------------------------------------------------
# 2. VERIFY AND STAGE REQUIRED BINARIES
# ----------------------------------------------------
Write-Host "[2/4] Verifying and staging packaging dependencies..." -ForegroundColor Cyan

if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}

$InstallerDir = Join-Path $RootDir "installer"
$WizBmp = Join-Path $InstallerDir "wizard.bmp"
$WizSmallBmp = Join-Path $InstallerDir "wizardsmall.bmp"
$IconPath = Join-Path $InstallerDir "phantomtrace.ico"

if (-not (Test-Path $IconPath) -or -not (Test-Path $WizBmp) -or -not (Test-Path $WizSmallBmp)) {
    Write-Host "      Generating official branding assets..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "generate_icon.ps1")
}

# 2a. Verify or build background agent service (PhantomTraceAgent.exe)
$agentDistDir = Join-Path $RootDir "phantomtrace-agent\dist\PhantomTraceAgent"
$agentExe = Join-Path $agentDistDir "PhantomTraceAgent.exe"
if (-not (Test-Path $agentExe)) {
    $specPath = Join-Path $RootDir "PhantomTraceAgent.spec"
    if (-not (Test-Path $specPath)) {
        $foundSpec = Get-ChildItem -Path $RootDir -Filter "PhantomTraceAgent.spec" -Recurse -File -Exclude node_modules | Select-Object -First 1
        if ($foundSpec) { $specPath = $foundSpec.FullName }
    }
    if (-not $specPath -or -not (Test-Path $specPath)) {
        Write-Error "Pre-compile check failed: Cannot locate PhantomTraceAgent.spec to build background agent."
        exit 1
    }
    Write-Host "      Building background agent service via $specPath..." -ForegroundColor Cyan
    Push-Location $RootDir
    try {
        & pyinstaller $specPath --clean --distpath (Join-Path $RootDir "phantomtrace-agent\dist")
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-Path $agentExe)) {
    Write-Error "Pre-compile check failed: Background agent service binary not found at '$agentExe'."
    exit 1
}
$agentSize = (Get-Item $agentExe).Length
if ($agentSize -le 0) {
    Write-Error "Pre-compile check failed: Background agent service binary at '$agentExe' is empty (0 bytes)."
    exit 1
}
Write-Host "      Verified Agent Service: $agentExe ($agentSize bytes)" -ForegroundColor Green

# 2b. Verify or stage scanner CLI binary
$resolvedScannerDir = $ScannerDir
$stagedScanner = Join-Path $RootDir "scanner_staged"
$expectedScannerName = "PhantomTrace_Windows_Release_1.0.exe"

if (-not $resolvedScannerDir -or -not (Test-Path $resolvedScannerDir)) {
    if (Test-Path (Join-Path $stagedScanner $expectedScannerName)) {
        $resolvedScannerDir = $stagedScanner
    }
    elseif (Test-Path (Join-Path $RootDir "release_bin\PhantomTrace-Agent.exe")) {
        if (-not (Test-Path $stagedScanner)) { New-Item -ItemType Directory -Path $stagedScanner -Force | Out-Null }
        Copy-Item (Join-Path $RootDir "release_bin\PhantomTrace-Agent.exe") -Destination (Join-Path $stagedScanner $expectedScannerName) -Force
        $resolvedScannerDir = $stagedScanner
    }
    else {
        # Build scanner CLI via agent/main.py
        Write-Host "      Building scanner CLI via build_and_sign_agent.ps1..." -ForegroundColor Cyan
        & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build_and_sign_agent.ps1")
        if (Test-Path (Join-Path $RootDir "release_bin\PhantomTrace-Agent.exe")) {
            if (-not (Test-Path $stagedScanner)) { New-Item -ItemType Directory -Path $stagedScanner -Force | Out-Null }
            Copy-Item (Join-Path $RootDir "release_bin\PhantomTrace-Agent.exe") -Destination (Join-Path $stagedScanner $expectedScannerName) -Force
            $resolvedScannerDir = $stagedScanner
        }
    }
}

if (-not $resolvedScannerDir -or -not (Test-Path $resolvedScannerDir)) {
    Write-Error "Pre-compile check failed: Could not resolve or stage scanner directory."
    exit 1
}

$scannerExe = Join-Path $resolvedScannerDir $expectedScannerName
if (-not (Test-Path $scannerExe)) {
    Write-Error "Pre-compile check failed: $expectedScannerName not found in $resolvedScannerDir."
    exit 1
}
$scannerSize = (Get-Item $scannerExe).Length
if ($scannerSize -le 0) {
    Write-Error "Pre-compile check failed: Scanner binary at '$scannerExe' is empty (0 bytes)."
    exit 1
}
Write-Host "      Verified Scanner Binary: $scannerExe ($scannerSize bytes)" -ForegroundColor Green

# ----------------------------------------------------
# 3. COMPILE INSTALLER
# ----------------------------------------------------
Write-Host "[3/4] Compiling PhantomTrace_Agent_Setup.exe..." -ForegroundColor Cyan

$isccArgs = @(
    "/DMyAppVersion=$Version",
    "/DScannerDir=$resolvedScannerDir",
    $InstallerIss
)

Push-Location (Join-Path $RootDir "installer")
try {
    & $IsccExe $isccArgs
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

$compiledSize = (Get-Item $DistInstaller).Length
if ($compiledSize -le 0) {
    Write-Error "Compiled installer at $DistInstaller is empty (0 bytes)."
    exit 1
}
Write-Host "      Compiled successfully: $DistInstaller ($compiledSize bytes)" -ForegroundColor Green

# ----------------------------------------------------
# 4. CALCULATE CHECKSUM & GENERATE RELEASE METADATA
# ----------------------------------------------------
Write-Host "[4/4] Generating release manifest and SHA-256 checksum..." -ForegroundColor Cyan

$finalInstaller = Get-Item $DistInstaller
$finalSize = $finalInstaller.Length
$finalSha256 = (Get-FileHash $DistInstaller -Algorithm SHA256).Hash.ToLower()

Write-Host "      Final Artifact:   $($finalInstaller.Name)" -ForegroundColor Green
Write-Host "      File Size:        $finalSize bytes" -ForegroundColor Green
Write-Host "      SHA-256 Checksum: $finalSha256" -ForegroundColor Yellow

# Standard sha256 manifest: <hash> *PhantomTrace_Agent_Setup.exe
$ManifestPath = Join-Path $DistDir "PhantomTrace_Agent_Setup.exe.sha256"
"$finalSha256 *$($finalInstaller.Name)" | Set-Content -Path $ManifestPath -Encoding UTF8 -NoNewline
Write-Host "      Created manifest: $ManifestPath" -ForegroundColor Gray

# Machine-readable release metadata (Explicitly Unsigned)
$releaseMetadata = [PSCustomObject]@{
    productName        = "PhantomTrace Windows Agent"
    version            = $Version
    filename           = $finalInstaller.Name
    fileSizeBytes      = $finalSize
    sha256             = $finalSha256
    downloadUrl        = "/downloads/$($finalInstaller.Name)"
    builtAtUtc         = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    signatureStatus    = "Unsigned"
    isProductionSigned = $false
    publisher          = $null
    notes              = "Explicitly unsigned release. SHA-256 checksum validates binary integrity only and does not establish publisher identity."
}

$MetadataJsonPath = Join-Path $DistDir "release_metadata.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($MetadataJsonPath, ($releaseMetadata | ConvertTo-Json -Depth 4), $utf8NoBom)
Write-Host "      Created metadata: $MetadataJsonPath" -ForegroundColor Gray

# ----------------------------------------------------
# ISOLATION NOTICE
# ----------------------------------------------------
Write-Host ""
Write-Host "STAGE ISOLATION: Installer is explicitly UNSIGNED." -ForegroundColor Yellow
Write-Host "Public distribution targets (public/, public/downloads/) and production metadata were NOT modified." -ForegroundColor Green
Write-Host "Unsigned release artifacts are safely isolated in: $DistDir" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host " INSTALLER PIPELINE COMPLETE - UNSIGNED BUILD READY" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
exit 0
