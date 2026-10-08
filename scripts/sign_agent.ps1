<#
.SYNOPSIS
    Production Authenticode Code Signing & Verification Script for PhantomTrace-Agent.exe

.DESCRIPTION
    Signs and verifies the PhantomTrace Windows Agent executable using Authenticode,
    SHA-256 digest algorithm, and RFC 3161 compliant timestamping.

    SECURITY CONSTRAINTS:
    - Never uses or creates self-signed certificates.
    - Never prints or exposes private keys, certificates, or passwords.
    - Halts immediately if production signing credentials/provider are not configured.
    - Fails if signature verification does not pass.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExePath = "",

    [Parameter(Mandatory = $false)]
    [string]$TimestampUrl = "http://timestamp.digicert.com",

    [Parameter(Mandatory = $false)]
    [ValidateSet("SHA256", "SHA384", "SHA512")]
    [string]$HashAlgorithm = "SHA256"
)

if (-not $ExePath) {
    $ExePath = Join-Path $PSScriptRoot "..\release_bin\PhantomTrace-Agent.exe"
}

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE CODE SIGNING PIPELINE" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. VERIFY EXECUTABLE
# ----------------------------------------------------
$ResolvedExe = Resolve-Path $ExePath -ErrorAction SilentlyContinue
if (-not $ResolvedExe -or -not (Test-Path $ResolvedExe)) {
    Write-Error "Executable not found at path: '$ExePath'. Please run the PyInstaller build first."
    exit 1
}

Write-Host "[1/4] Target binary verified: $ResolvedExe" -ForegroundColor Green

# ----------------------------------------------------
# 2. CHECK PRODUCTION SIGNING CONFIGURATION
# ----------------------------------------------------
$Thumbprint = $env:CODE_SIGNING_CERT_THUMBPRINT
$PfxPath    = $env:CODE_SIGNING_PFX_PATH
$PfxPass    = $env:CODE_SIGNING_PFX_PASSWORD

$HasStoreCert = [bool]$Thumbprint
$HasPfxFile   = [bool]($PfxPath -and (Test-Path $PfxPath))
$HasAzureSign = [bool]($env:AZURE_TRUSTED_SIGNING_ENDPOINT -and $env:AZURE_TRUSTED_SIGNING_ACCOUNT)

if (-not $HasStoreCert -and -not $HasPfxFile -and -not $HasAzureSign) {
    Write-Warning "Production signing certificate/provider is not configured."
    Write-Host ""
    Write-Host "To configure production Authenticode signing, provide one of the following:" -ForegroundColor Yellow
    Write-Host "  1. Certificate Store: Set `$env:CODE_SIGNING_CERT_THUMBPRINT with your installed EV/OV Code Signing Certificate."
    Write-Host "  2. PFX Certificate:   Set `$env:CODE_SIGNING_PFX_PATH and `$env:CODE_SIGNING_PFX_PASSWORD in secure environment variables or CI/CD secrets."
    Write-Host "  3. Azure Trusted:     Set `$env:AZURE_TRUSTED_SIGNING_ENDPOINT and `$env:AZURE_TRUSTED_SIGNING_ACCOUNT."
    Write-Host ""
    Write-Host "SECURITY NOTICE: Self-signed certificates are prohibited for production release." -ForegroundColor Red
    Write-Host "STOPPING: Unsigned binary will NOT be released as signed." -ForegroundColor Red
    exit 2
}

# ----------------------------------------------------
# 3. AUTHENTICODE SIGNING EXECUTION
# ----------------------------------------------------
Write-Host "[2/4] Executing Authenticode signing with $HashAlgorithm and RFC 3161 timestamping..." -ForegroundColor Cyan

# Locate signtool.exe if available in Windows SDKs
$SignTool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
if (-not $SignTool) {
    $SdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
    )
    $FoundSignTools = Get-ChildItem -Path $SdkPaths -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
    if ($FoundSignTools) {
        $SignTool = $FoundSignTools[0].FullName
    }
}

$SignSuccess = $false

if ($SignTool) {
    Write-Host "      Using Microsoft SignTool: $SignTool" -ForegroundColor Gray

    if ($HasStoreCert) {
        $signArgs = @("sign", "/fd", $HashAlgorithm, "/sha1", $Thumbprint, "/tr", $TimestampUrl, "/td", $HashAlgorithm, "/v", $ResolvedExe.Path)
        & $SignTool $signArgs
        if ($LASTEXITCODE -eq 0) { $SignSuccess = $true }
    }
    elseif ($HasPfxFile) {
        $signArgs = @("sign", "/f", $PfxPath, "/p", $PfxPass, "/fd", $HashAlgorithm, "/tr", $TimestampUrl, "/td", $HashAlgorithm, "/v", $ResolvedExe.Path)
        & $SignTool $signArgs
        if ($LASTEXITCODE -eq 0) { $SignSuccess = $true }
    }
}
else {
    Write-Host "      SignTool not in PATH; falling back to PowerShell Set-AuthenticodeSignature..." -ForegroundColor Gray

    $Cert = $null
    if ($HasStoreCert) {
        $Cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
        if (-not $Cert) {
            $Cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
        }
    }
    elseif ($HasPfxFile) {
        $SecurePass = if ($PfxPass) { ConvertTo-SecureString $PfxPass -AsPlainText -Force } else { $null }
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $SecurePass)
    }

    if (-not $Cert) {
        Write-Error "Failed to load signing certificate from specified configuration."
        exit 1
    }

    $sigResult = Set-AuthenticodeSignature -FilePath $ResolvedExe.Path -Certificate $Cert -HashAlgorithm $HashAlgorithm -TimestampServer $TimestampUrl
    if ($sigResult.Status -eq "Valid") {
        $SignSuccess = $true
    } else {
        Write-Error "Set-AuthenticodeSignature failed with status: $($sigResult.Status) - $($sigResult.StatusMessage)"
        exit 1
    }
}

if (-not $SignSuccess) {
    Write-Error "Signing execution failed. Build aborted to prevent publishing unsigned binary."
    exit 1
}

Write-Host "[3/4] Authenticode signing applied successfully." -ForegroundColor Green

# ----------------------------------------------------
# 4. SIGNATURE VERIFICATION
# ----------------------------------------------------
Write-Host "[4/4] Verifying signature validity and timestamp..." -ForegroundColor Cyan

$Signature = Get-AuthenticodeSignature -FilePath $ResolvedExe.Path
Write-Host "      Status:                $($Signature.Status)"
Write-Host "      Status Message:        $($Signature.StatusMessage)"

if ($Signature.SignerCertificate) {
    Write-Host "      Publisher Subject:     $($Signature.SignerCertificate.Subject)" -ForegroundColor Green
    Write-Host "      Certificate Issuer:    $($Signature.SignerCertificate.Issuer)" -ForegroundColor Green
    Write-Host "      Certificate Expiration:$($Signature.SignerCertificate.NotAfter)"
}

if ($Signature.TimeStamperCertificate) {
    Write-Host "      Timestamp Authority:   $($Signature.TimeStamperCertificate.Subject)" -ForegroundColor Green
}

if ($Signature.Status -ne "Valid") {
    Write-Error "Signature verification FAILED. Status: $($Signature.Status). Binary cannot be released."
    exit 1
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host " SIGNATURE VERIFICATION PASSED: PRODUCTION READY" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
exit 0
