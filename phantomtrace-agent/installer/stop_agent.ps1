<#
.SYNOPSIS
    Stops the running PhantomTrace Windows Agent service.
.DESCRIPTION
    Safely terminates background PhantomTrace Agent processes (PhantomTraceAgent.exe or Python service)
    and ensures localhost port 49152 is released.
#>

param(
    [int]$Port = 49152
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE WINDOWS AGENT — STOPPING SERVICE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Stop executable instances
$agentProcesses = Get-Process -Name "PhantomTraceAgent", "PhantomTrace-Agent" -ErrorAction SilentlyContinue
if ($agentProcesses) {
    $count = $agentProcesses.Count
    $agentProcesses | Stop-Process -Force
    Write-Host "[✓] Terminated $count running PhantomTraceAgent executable process(es)." -ForegroundColor Green
} else {
    Write-Host "[-] No PhantomTraceAgent executable processes currently running."
}

# 2. Check and free port 49152 if bound by a Python agent process
$connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
foreach ($conn in $connections) {
    if ($conn.OwningProcess -gt 0) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and ($proc.ProcessName -match "python" -or $proc.ProcessName -match "PhantomTrace")) {
                Stop-Process -Id $conn.OwningProcess -Force
                Write-Host "[✓] Terminated process $($conn.OwningProcess) ($($proc.ProcessName)) holding port $Port." -ForegroundColor Green
            }
        } catch {
            Write-Warning "Could not stop process $($conn.OwningProcess): $_"
        }
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PhantomTrace Agent stopped successfully." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
