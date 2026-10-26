<#
.SYNOPSIS
    Uninstalls the PhantomTrace Windows Agent shortcuts and configuration.
.DESCRIPTION
    Safely terminates running agent processes, removes Desktop, Start Menu,
    and Startup shortcuts, and cleans up registry entries while preserving user data.
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\PhantomTraceAgent",
    [int]$Port = 49152,
    [switch]$PurgeUserData = $false
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE WINDOWS AGENT — UNINSTALLATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Terminate running agent processes
Write-Host "[1/4] Stopping active PhantomTrace Agent processes..."
Get-Process -Name "PhantomTraceAgent", "PhantomTrace-Agent" | Stop-Process -Force
Get-NetTCPConnection -LocalPort $Port | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
Write-Host "      [✓] Processes stopped." -ForegroundColor Green

# 2. Remove Desktop and Start Menu shortcuts
Write-Host "[2/4] Removing application shortcuts..."
$desktopDir = [Environment]::GetFolderPath("Desktop")
@("PhantomTrace.lnk", "PhantomTrace Windows Agent.lnk") | ForEach-Object {
    $p = Join-Path $desktopDir $_
    if (Test-Path $p) { Remove-Item -Path $p -Force }
}

$programsDir = [Environment]::GetFolderPath("Programs")
@("PhantomTrace", "PhantomTrace Windows Agent") | ForEach-Object {
    $p = Join-Path $programsDir $_
    if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force }
}
Write-Host "      [✓] Desktop and Start Menu shortcuts removed." -ForegroundColor Green

# 3. Remove Startup shortcuts and Registry Run entries
Write-Host "[3/4] Removing startup configuration..."
$startupDir = [Environment]::GetFolderPath("Startup")
@("PhantomTrace.lnk", "PhantomTrace Windows Agent.lnk") | ForEach-Object {
    $p = Join-Path $startupDir $_
    if (Test-Path $p) { Remove-Item -Path $p -Force }
}

$regKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
@("PhantomTrace", "PhantomTraceAgent", "PhantomTrace Windows Agent") | ForEach-Object {
    Remove-ItemProperty -Path $regKeyPath -Name $_ -ErrorAction SilentlyContinue
}
Write-Host "      [✓] Startup shortcuts and registry entries removed." -ForegroundColor Green

# 4. Clean Install Directory (Preserving user data unless -PurgeUserData)
Write-Host "[4/4] Removing installed launcher scripts..."
if (Test-Path $InstallDir) {
    Remove-Item -Path (Join-Path $InstallDir "start_agent.bat") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $InstallDir "stop_agent.bat") -Force -ErrorAction SilentlyContinue

    if ($PurgeUserData) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Host "      [Purged] All local user data removed." -ForegroundColor Yellow
    } else {
        Write-Host "      [Preserved] User scan data and credentials preserved in: $InstallDir" -ForegroundColor Green
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " UNINSTALLATION COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
