<#
.SYNOPSIS
    Build Automation for PhantomTrace Windows Agent Scanner CLI (PhantomTrace-Agent.exe) - Unsigned

.DESCRIPTION
    1. Compiles PhantomTrace-Agent.exe using PyInstaller into release_bin/
    2. Verifies output binary exists and is nonempty
    3. Retains binary isolated in release_bin/ without modifying public production downloads
#>

[CmdletBinding()]
param(
    [switch]$SkipSigningIfUnconfigured = $false, # Retained for compatibility
    [switch]$AllowDevSelfSigned = $false,        # Retained for compatibility
    [string]$ExpectedPublisher = ""              # Retained for compatibility
)

$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$ReleaseBinDir = Join-Path $RootDir "release_bin"
$AgentExe = Join-Path $ReleaseBinDir "PhantomTrace-Agent.exe"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE - BUILD SCANNER CLI (UNSIGNED)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. BUILD WITH PYINSTALLER
# ----------------------------------------------------
Write-Host "[1/2] Building PhantomTrace-Agent.exe with PyInstaller..." -ForegroundColor Cyan

if (-not (Test-Path $ReleaseBinDir)) {
    New-Item -ItemType Directory -Path $ReleaseBinDir -Force | Out-Null
}

$IconPath = Join-Path $RootDir "installer\phantomtrace.ico"
if (-not (Test-Path $IconPath)) {
    Write-Host "      Generating official Windows icon..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "generate_icon.ps1")
}

$pyinstallerArgs = @(
    "--name", "PhantomTrace-Agent",
    "--onefile",
    "--noconsole",
    "--clean",
    "--icon", $IconPath,
    "--paths", ".",
    "--distpath", "release_bin",
    "--hidden-import", "agent",
    "--hidden-import", "agent.core",
    "--hidden-import", "agent.core.baseline",
    "--hidden-import", "agent.core.behavior_engine",
    "--hidden-import", "agent.core.memory_analyzer",
    "--hidden-import", "agent.core.memory_scanner",
    "--hidden-import", "agent.core.process_scanner",
    "--hidden-import", "agent.core.threat_score",
    "--hidden-import", "agent.notifications",
    "--hidden-import", "alert_history",
    "--hidden-import", "psutil",
    "agent/main.py"
)

Push-Location $RootDir
try {
    & pyinstaller $pyinstallerArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "PyInstaller build failed with exit code $LASTEXITCODE."
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path $AgentExe)) {
    Write-Error "Build completed but $AgentExe was not found."
    exit 1
}

$FileSize = (Get-Item $AgentExe).Length
if ($FileSize -le 0) {
    Write-Error "Built binary at $AgentExe is empty (0 bytes)."
    exit 1
}

Write-Host "      Build succeeded: $AgentExe ($FileSize bytes)" -ForegroundColor Green

# ----------------------------------------------------
# 2. STATUS & ISOLATION
# ----------------------------------------------------
Write-Host "[2/2] Release status: Unsigned binary safely isolated in $ReleaseBinDir." -ForegroundColor Yellow
Write-Host "      Public production downloads were NOT modified." -ForegroundColor Green

Write-Host "====================================================" -ForegroundColor Green
Write-Host " SCANNER CLI BUILD COMPLETE (UNSIGNED)" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
exit 0
