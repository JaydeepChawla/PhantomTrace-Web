<#
.SYNOPSIS
    Installs and launches the PhantomTrace Windows Agent service.
.DESCRIPTION
    Sets up the local PhantomTrace Agent orchestration service on 127.0.0.1:49152.
    Enables one-click "Scan My PC" from the PhantomTrace web console.
    100% Read-Only inspection model. Never alters system files.
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\PhantomTraceAgent",
    [int]$Port = 49152,
    [switch]$StartNow = $true
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE WINDOWS AGENT INSTALLATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify / Create Destination Directory
Write-Host "[1/4] Configuring installation directory: $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Check Python Runtime
Write-Host "[2/4] Verifying Python runtime..."
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    Write-Warning "Python runtime not detected in system PATH. Please ensure Python 3.8+ is installed."
} else {
    Write-Host "      Detected Python at: $pythonPath" -ForegroundColor Green
}

# 3. Create Desktop / Startup Shortcut (Optional User Convenience)
Write-Host "[3/4] Registering local service configuration..."
$startScript = Join-Path $InstallDir "start_agent.bat"
$scriptContent = @"
@echo off
title PhantomTrace Windows Agent
cd /d "%~dp0"
python -m agent_service.main
pause
"@
Set-Content -Path $startScript -Value $scriptContent -Encoding ASCII

# 4. Starting Service if requested
if ($StartNow) {
    Write-Host "[4/4] Launching PhantomTrace Agent on 127.0.0.1:$Port..." -ForegroundColor Cyan
    $agentScript = Join-Path $PSScriptRoot "..\agent_service\main.py"
    if (Test-Path $agentScript) {
        Start-Process python -ArgumentList "-m agent_service.main" -WorkingDirectory (Join-Path $PSScriptRoot "..")
        Write-Host "      PhantomTrace Agent is now running in the background." -ForegroundColor Green
        Write-Host "      Web console will now detect: 'PhantomTrace Agent Connected'." -ForegroundColor Green
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " INSTALLATION COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
