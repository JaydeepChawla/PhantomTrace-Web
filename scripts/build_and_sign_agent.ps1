<#
.SYNOPSIS
    Build and Sign Automation for PhantomTrace Windows Agent

.DESCRIPTION
    1. Compiles PhantomTrace-Agent.exe using PyInstaller into release_bin/
    2. Runs Authenticode code signing with SHA-256 and RFC 3161 timestamping
    3. Verifies the digital signature
    4. Halts if signing fails or credentials are missing (strict production mode)
#>

[CmdletBinding()]
param(
    [switch]$SkipSigningIfUnconfigured = $false
)

$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$ReleaseBinDir = Join-Path $RootDir "release_bin"
$AgentExe = Join-Path $ReleaseBinDir "PhantomTrace-Agent.exe"
$PublicDownloads = Join-Path $RootDir "public\downloads"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE — BUILD & SIGN AGENT PIPELINE" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. BUILD WITH PYINSTALLER
# ----------------------------------------------------
Write-Host "[1/3] Building PhantomTrace-Agent.exe with PyInstaller..." -ForegroundColor Cyan

if (-not (Test-Path $ReleaseBinDir)) {
    New-Item -ItemType Directory -Path $ReleaseBinDir -Force | Out-Null
}

$pyinstallerArgs = @(
    "--name", "PhantomTrace-Agent",
    "--onefile",
    "--clean",
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
Write-Host "      Build succeeded: $AgentExe ($FileSize bytes)" -ForegroundColor Green

# ----------------------------------------------------
# 2. CODE SIGNING
# ----------------------------------------------------
Write-Host "[2/3] Initiating Authenticode code signing..." -ForegroundColor Cyan

$SignScript = Join-Path $PSScriptRoot "sign_agent.ps1"
$SignExitCode = 0

try {
    & $SignScript -ExePath $AgentExe
    $SignExitCode = $LASTEXITCODE
}
catch {
    $SignExitCode = 1
}

if ($SignExitCode -eq 2) {
    # Production certificate not configured
    if ($SkipSigningIfUnconfigured) {
        Write-Warning "Skipping code signing because production credentials are not configured and -SkipSigningIfUnconfigured was passed."
        Write-Warning "NOTE: This binary is UNSIGNED and must NOT be deployed to production."
    }
    else {
        Write-Error "Production signing certificate/provider is not configured. Stopping build to prevent publishing unsigned binary."
        exit 2
    }
}
elseif ($SignExitCode -ne 0) {
    Write-Error "Code signing failed. Binary cannot be published."
    exit 1
}
else {
    Write-Host "[3/3] Authenticode signature verified and ready for distribution." -ForegroundColor Green
    if (Test-Path $PublicDownloads) {
        Copy-Item -Path $AgentExe -Destination (Join-Path $PublicDownloads "PhantomTrace-Agent.exe") -Force
    }
}

Write-Host "====================================================" -ForegroundColor Green
Write-Host " AGENT PIPELINE COMPLETE" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
