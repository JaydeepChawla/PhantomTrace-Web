<#
.SYNOPSIS
    Digital Signature Inspector & Compatibility Utility for PhantomTrace Executables
.DESCRIPTION
    Inspects and reports the digital signature status of PhantomTrace Windows executables.
    Code signing requirements (Azure Artifact Signing, Authenticode signing, publisher gates)
    have been retired. PhantomTrace distributes explicitly unsigned artifacts with SHA-256
    integrity checksums.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExePath = "",

    [Parameter(Mandatory = $false)]
    [string]$TimestampUrl = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("SHA256", "SHA384", "SHA512")]
    [string]$HashAlgorithm = "SHA256",

    [Parameter(Mandatory = $false)]
    [switch]$AllowDevSelfSigned = $false,

    [Parameter(Mandatory = $false)]
    [string]$ExpectedPublisher = ""
)

if (-not $ExePath) {
    $ExePath = Join-Path $PSScriptRoot "..\release_bin\PhantomTrace-Agent.exe"
}

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE DIGITAL SIGNATURE STATUS INSPECTOR" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. VERIFY TARGET EXECUTABLE
# ----------------------------------------------------
$ResolvedExe = Resolve-Path $ExePath -ErrorAction SilentlyContinue
if (-not $ResolvedExe -or -not (Test-Path $ResolvedExe)) {
    Write-Error "Executable not found at path: '$ExePath'."
    exit 1
}

$FileSize = (Get-Item $ResolvedExe).Length
Write-Host "[1/2] Target binary verified: $($ResolvedExe.Path) ($FileSize bytes)" -ForegroundColor Green

# ----------------------------------------------------
# 2. REPORT SIGNATURE STATUS (NO CODE SIGNING ENFORCED)
# ----------------------------------------------------
Write-Host "[2/2] Checking Authenticode signature status..." -ForegroundColor Cyan

$Signature = Get-AuthenticodeSignature -FilePath $ResolvedExe.Path
Write-Host "      Authenticode Status: $($Signature.Status)" -ForegroundColor Gray

if ($Signature.SignerCertificate) {
    Write-Host "      Signer Subject:      $($Signature.SignerCertificate.Subject)" -ForegroundColor Gray
} else {
    Write-Host "      Signing Policy:      Explicitly Unsigned (No code signing credentials required)" -ForegroundColor Green
}

$fileHash = (Get-FileHash $ResolvedExe.Path -Algorithm SHA256).Hash.ToLower()
Write-Host "      SHA-256 Checksum:    $fileHash" -ForegroundColor Yellow

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host " NOTICE: PhantomTrace distributes explicitly unsigned artifacts." -ForegroundColor Green
Write-Host " SHA-256 validates file integrity only; no Authenticode signature required." -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
exit 0
