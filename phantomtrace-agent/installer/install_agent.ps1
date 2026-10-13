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
    [bool]$StartNow = $false
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE WINDOWS AGENT INSTALLATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify / Create Destination Directory
Write-Host "[1/5] Configuring installation directory: $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Check Python Runtime
Write-Host "[2/5] Verifying Python runtime..."
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    Write-Warning "Python runtime not detected in system PATH. Please ensure Python 3.8+ is installed."
} else {
    Write-Host "      Detected Python at: $pythonPath" -ForegroundColor Green
}

# 3. Create Local Control Scripts (Windowless Launch & Clean Stop)
Write-Host "[3/5] Registering local service scripts..."
$startScript = Join-Path $InstallDir "start_agent.bat"
$scriptContent = @"
@echo off
cd /d "%~dp0"
start "" pythonw -m agent_service.main
"@
Set-Content -Path $startScript -Value $scriptContent -Encoding ASCII

$stopScript = Join-Path $InstallDir "stop_agent.bat"
$stopScriptContent = @"
@echo off
powershell -NoProfile -Command "Get-Process -Name 'PhantomTraceAgent', 'PhantomTrace-Agent' -ErrorAction SilentlyContinue | Stop-Process -Force; Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id `$_.OwningProcess -Force -ErrorAction SilentlyContinue }"
echo PhantomTrace Agent stopped.
"@
Set-Content -Path $stopScript -Value $stopScriptContent -Encoding ASCII

# 4. Create Desktop & Start Menu Shortcuts (Manual Launch)
Write-Host "[4/5] Creating application shortcuts..."
$wscript = New-Object -ComObject WScript.Shell

# Desktop Shortcut
$desktopDir = [Environment]::GetFolderPath("Desktop")
$desktopLnk = Join-Path $desktopDir "PhantomTrace.lnk"
$dtShortcut = $wscript.CreateShortcut($desktopLnk)
$dtShortcut.TargetPath = $startScript
$dtShortcut.WorkingDirectory = $InstallDir
$dtShortcut.Description = "Launch PhantomTrace Windows Agent"
$dtShortcut.Save()
Write-Host "      [✓] Desktop shortcut created: $desktopLnk" -ForegroundColor Green

# Start Menu Shortcuts
$programsDir = [Environment]::GetFolderPath("Programs")
$startMenuDir = Join-Path $programsDir "PhantomTrace"
if (-not (Test-Path $startMenuDir)) {
    New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null
}

$smLnk = Join-Path $startMenuDir "PhantomTrace.lnk"
$smShortcut = $wscript.CreateShortcut($smLnk)
$smShortcut.TargetPath = $startScript
$smShortcut.WorkingDirectory = $InstallDir
$smShortcut.Description = "Launch PhantomTrace Windows Agent"
$smShortcut.Save()

$smStopLnk = Join-Path $startMenuDir "Stop PhantomTrace Agent.lnk"
$smStopShortcut = $wscript.CreateShortcut($smStopLnk)
$smStopShortcut.TargetPath = $stopScript
$smStopShortcut.WorkingDirectory = $InstallDir
$smStopShortcut.Description = "Stop PhantomTrace Windows Agent"
$iconFile = Join-Path $InstallDir "phantomtrace.ico"
if (-not (Test-Path $iconFile)) {
    $repoIcon = Join-Path $PSScriptRoot "phantomtrace.ico"
    if (Test-Path $repoIcon) {
        Copy-Item -Path $repoIcon -Destination $iconFile -Force -ErrorAction SilentlyContinue
    }
}
if (Test-Path $iconFile) {
    $dtShortcut.IconLocation = "$iconFile,0"
    $dtShortcut.Save()
    $smShortcut.IconLocation = "$iconFile,0"
    $smShortcut.Save()
    $smStopShortcut.IconLocation = "$iconFile,0"
    $smStopShortcut.Save()
}
Write-Host "      [✓] Start Menu shortcuts created: $startMenuDir" -ForegroundColor Green

# 5. Windows Startup Configuration (Automatic startup permanently removed)
Write-Host "[5/5] Ensuring automatic Windows startup is disabled..."
$startupDir = [Environment]::GetFolderPath("Startup")
$startupLnk = Join-Path $startupDir "PhantomTrace.lnk"
$legacyStartupLnk = Join-Path $startupDir "PhantomTrace Windows Agent.lnk"

# Ensure upgrading or reinstalling removes any unwanted automatic startup shortcuts
if (Test-Path $startupLnk) {
    Remove-Item -Path $startupLnk -Force -ErrorAction SilentlyContinue
}
if (Test-Path $legacyStartupLnk) {
    Remove-Item -Path $legacyStartupLnk -Force -ErrorAction SilentlyContinue
}
Write-Host "      [✓] Automatic Windows startup is disabled." -ForegroundColor Green
Write-Host "      The agent will only run when manually opened." -ForegroundColor Green

# 6. Starting Service ONLY if explicitly requested
if ($StartNow) {
    Write-Host "Launching PhantomTrace Agent on 127.0.0.1:$Port (explicitly requested)..." -ForegroundColor Cyan
    $agentScript = Join-Path $PSScriptRoot "..\agent_service\main.py"
    if (Test-Path $agentScript) {
        $pythonwPath = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
        if ($pythonwPath) {
            Start-Process pythonw -ArgumentList "-m agent_service.main" -WorkingDirectory (Join-Path $PSScriptRoot "..")
        } else {
            Start-Process python -ArgumentList "-m agent_service.main" -WorkingDirectory (Join-Path $PSScriptRoot "..") -WindowStyle Hidden
        }
        Write-Host "      PhantomTrace Agent is running in the background." -ForegroundColor Green
    }
} else {
    Write-Host "Agent is currently stopped." -ForegroundColor Yellow
    Write-Host "To launch PhantomTrace, double-click the desktop shortcut or run:" -ForegroundColor Cyan
    Write-Host "  $startScript" -ForegroundColor White
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " INSTALLATION COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
