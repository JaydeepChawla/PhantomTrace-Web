<#
.SYNOPSIS
    Authenticode Code Signing & Digital Signature Verification for PhantomTrace Executables

.DESCRIPTION
    Signs and verifies PhantomTrace Windows executables (Agent service, Scanner CLI, and Setup Installer)
    using Authenticode, SHA-256 digest algorithm, and RFC 3161 compliant timestamping.

    SECURITY ARCHITECTURE:
    1. Genuine Certificate: Supports commercial EV/OV code signing certificate via Windows Certificate
       Store (Thumbprint) or PFX file / base64 secret.
    2. Microsoft SignTool: Prefers Microsoft SignTool (signtool.exe) with RFC 3161 timestamp service.
       Falls back to PowerShell Set-AuthenticodeSignature when SignTool is not installed.
    3. Graceful / Optional Pipeline: If signing credentials are not configured, the script cleanly
       reports the artifact as explicitly unsigned and verifies SHA-256 integrity, UNLESS
       -FailIfUnconfigured is specified (in which case it fails clearly).
    4. Cryptographic Honesty: Never fabricates signatures, never presents self-signed certificates as
       publicly trusted, and never claims an unsigned binary is signed.
    5. Secret Protection: Never commits or logs private keys, passwords, or certificate bodies.
       Temporary decoded PFX files are scrubbed in a finally block.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExePath = "",

    [Parameter(Mandatory = $false)]
    [string]$TimestampUrl = "http://timestamp.digicert.com",

    [Parameter(Mandatory = $false)]
    [ValidateSet("SHA256", "SHA384", "SHA512")]
    [string]$HashAlgorithm = "SHA256",

    [Parameter(Mandatory = $false)]
    [switch]$FailIfUnconfigured = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSigningIfUnconfigured = $false, # Retained for backward compatibility

    [Parameter(Mandatory = $false)]
    [switch]$AllowDevSelfSigned = $false,        # Retained for backward compatibility

    [Parameter(Mandatory = $false)]
    [string]$ExpectedPublisher = "",

    [Parameter(Mandatory = $false)]
    [string]$PfxPath = "",

    [Parameter(Mandatory = $false)]
    [string]$PfxPassword = "",

    [Parameter(Mandatory = $false)]
    [string]$CertThumbprint = ""
)

if (-not $ExePath) {
    $ExePath = Join-Path $PSScriptRoot "..\release_bin\PhantomTrace-Agent.exe"
}

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " PHANTOMTRACE AUTHENTICODE SIGNING & VERIFICATION" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. VERIFY TARGET EXECUTABLE
# ----------------------------------------------------
$ResolvedExe = Resolve-Path $ExePath -ErrorAction SilentlyContinue
if (-not $ResolvedExe -or -not (Test-Path $ResolvedExe)) {
    throw "Target executable not found at path: '$ExePath'."
}

$FileSize = (Get-Item $ResolvedExe).Length
if ($FileSize -le 0) {
    throw "Target executable at '$($ResolvedExe.Path)' is empty (0 bytes)."
}
Write-Host "[1/3] Target binary verified: $($ResolvedExe.Path) ($FileSize bytes)" -ForegroundColor Green

# ----------------------------------------------------
# 2. DISCOVER SIGNING CREDENTIALS
# ----------------------------------------------------
$Thumbprint = if ($CertThumbprint) { $CertThumbprint } else { $env:CODE_SIGNING_CERT_THUMBPRINT }
$PfxFile    = if ($PfxPath) { $PfxPath } else { $env:CODE_SIGNING_PFX_PATH }
$PfxPass    = if ($PfxPassword) { $PfxPassword } else { $env:CODE_SIGNING_PFX_PASSWORD }
$PfxBase64  = $env:CODE_SIGNING_PFX_BASE64

$tempPfxCreated = $null

try {
    # If base64-encoded PFX is provided via CI secret, decode to secure temporary file
    if (-not $PfxFile -and $PfxBase64) {
        $tempPfxPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("pt_sign_" + [System.Guid]::NewGuid().ToString("N") + ".pfx"))
        [System.IO.File]::WriteAllBytes($tempPfxPath, [System.Convert]::FromBase64String($PfxBase64))
        $PfxFile = $tempPfxPath
        $tempPfxCreated = $tempPfxPath
    }

    $HasStoreCert = [bool]$Thumbprint
    $HasPfxFile   = [bool]($PfxFile -and (Test-Path $PfxFile))

    $IsSigningConfigured = $HasStoreCert -or $HasPfxFile

    if (-not $IsSigningConfigured) {
        if ($FailIfUnconfigured) {
            throw "Code signing certificate/provider is not configured. Aborting because signing was required (-FailIfUnconfigured)."
        }

        Write-Host "[2/3] Code signing credentials: Not configured." -ForegroundColor Yellow
        Write-Host "      No trusted certificate credentials found in environment or parameters." -ForegroundColor Gray
        Write-Host "      Proceeding with explicitly unsigned inspection." -ForegroundColor Gray

        Write-Host "[3/3] Inspecting digital signature status..." -ForegroundColor Cyan
        $Signature = Get-AuthenticodeSignature -FilePath $ResolvedExe.Path
        Write-Host "      Authenticode Status: $($Signature.Status)" -ForegroundColor Gray

        if ($Signature.Status -eq "Valid" -and $Signature.SignerCertificate) {
            Write-Host "      Publisher Subject:   $($Signature.SignerCertificate.Subject)" -ForegroundColor Green
            Write-Host "      Certificate Status:  Valid Authenticode Signature Present" -ForegroundColor Green
        } else {
            Write-Host "      Signing Policy:      Explicitly Unsigned (No code signing credentials applied)" -ForegroundColor Green
        }

        $fileHash = (Get-FileHash $ResolvedExe.Path -Algorithm SHA256).Hash.ToLower()
        Write-Host "      SHA-256 Checksum:    $fileHash" -ForegroundColor Yellow
        Write-Host "====================================================" -ForegroundColor Green
        Write-Host " VERIFICATION COMPLETE (UNSIGNED / PASSIVE)" -ForegroundColor Green
        Write-Host "====================================================" -ForegroundColor Green
        exit 0
    }

    # ----------------------------------------------------
    # 3. LOCATE MICROSOFT SIGNTOOL
    # ----------------------------------------------------
    Write-Host "[2/3] Preparing code signing execution..." -ForegroundColor Cyan

    $SignTool = $null
    $foundInPath = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($foundInPath) {
        $SignTool = $foundInPath.Source
    } else {
        $SdkPaths = @(
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
            "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe",
            "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\*\bin\NETFX *\x64\signtool.exe"
        )
        $FoundSignTools = Get-ChildItem -Path $SdkPaths -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
        if ($FoundSignTools) {
            $SignTool = $FoundSignTools[0].FullName
        }
    }

    $SignSuccess = $false

    # ----------------------------------------------------
    # 4. EXECUTE AUTHENTICODE SIGNING
    # ----------------------------------------------------
    if ($SignTool -and (Test-Path $SignTool)) {
        Write-Host "      Using Microsoft SignTool: $SignTool" -ForegroundColor Gray
        Write-Host "      Hash Algorithm:          $HashAlgorithm" -ForegroundColor Gray
        Write-Host "      RFC 3161 Timestamp URL:  $TimestampUrl" -ForegroundColor Gray

        if ($HasStoreCert) {
            Write-Host "      Signing with Certificate Store Thumbprint..." -ForegroundColor Gray
            $signArgs = @("sign", "/fd", $HashAlgorithm, "/sha1", $Thumbprint, "/tr", $TimestampUrl, "/td", $HashAlgorithm, "/v", $ResolvedExe.Path)
            & $SignTool $signArgs
            if ($LASTEXITCODE -eq 0) { $SignSuccess = $true }
        }
        elseif ($HasPfxFile) {
            Write-Host "      Signing with PFX Certificate..." -ForegroundColor Gray
            $signArgs = if ($PfxPass) {
                @("sign", "/f", $PfxFile, "/p", $PfxPass, "/fd", $HashAlgorithm, "/tr", $TimestampUrl, "/td", $HashAlgorithm, "/v", $ResolvedExe.Path)
            } else {
                @("sign", "/f", $PfxFile, "/fd", $HashAlgorithm, "/tr", $TimestampUrl, "/td", $HashAlgorithm, "/v", $ResolvedExe.Path)
            }
            & $SignTool $signArgs
            if ($LASTEXITCODE -eq 0) { $SignSuccess = $true }
        }
    }
    else {
        Write-Host "      SignTool not found; using PowerShell Set-AuthenticodeSignature..." -ForegroundColor Gray

        $Cert = $null
        if ($HasStoreCert) {
            $Cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
            if (-not $Cert) {
                $Cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
            }
        }
        elseif ($HasPfxFile) {
            $Cert = if ($PfxPass) {
                $secPass = ConvertTo-SecureString $PfxPass -AsPlainText -Force
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxFile, $secPass)
            } else {
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxFile)
            }
        }

        if (-not $Cert) {
            throw "Failed to load signing certificate from specified configuration."
        }

        $sigResult = Set-AuthenticodeSignature -FilePath $ResolvedExe.Path -Certificate $Cert -HashAlgorithm $HashAlgorithm -TimestampServer $TimestampUrl
        if ($sigResult.Status -eq "Valid") {
            $SignSuccess = $true
        } else {
            throw "Set-AuthenticodeSignature failed with status: $($sigResult.Status) - $($sigResult.StatusMessage)"
        }
    }

    if (-not $SignSuccess) {
        throw "Authenticode signing command failed for $($ResolvedExe.Path)."
    }

    # ----------------------------------------------------
    # 5. VERIFY DIGITAL SIGNATURE
    # ----------------------------------------------------
    Write-Host "[3/3] Verifying Authenticode signature and timestamp..." -ForegroundColor Cyan

    if ($SignTool -and (Test-Path $SignTool)) {
        Write-Host "      Running SignTool verification..." -ForegroundColor Gray
        & $SignTool verify /pa /v $ResolvedExe.Path
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool verification failed with exit code $LASTEXITCODE."
        }
    }

    $Signature = Get-AuthenticodeSignature -FilePath $ResolvedExe.Path
    Write-Host "      Authenticode Status:    $($Signature.Status)" -ForegroundColor Green

    if ($Signature.SignerCertificate) {
        Write-Host "      Publisher Subject:      $($Signature.SignerCertificate.Subject)" -ForegroundColor Green
        Write-Host "      Certificate Issuer:     $($Signature.SignerCertificate.Issuer)" -ForegroundColor Green
        Write-Host "      Certificate Expiration: $($Signature.SignerCertificate.NotAfter)" -ForegroundColor Gray
    }

    if ($Signature.TimeStamperCertificate) {
        Write-Host "      Timestamp Authority:    $($Signature.TimeStamperCertificate.Subject)" -ForegroundColor Green
    }

    if ($ExpectedPublisher -and $Signature.SignerCertificate) {
        if (-not ($Signature.SignerCertificate.Subject -like "*$ExpectedPublisher*")) {
            throw "Publisher mismatch: Expected '$ExpectedPublisher', got '$($Signature.SignerCertificate.Subject)'."
        }
    }

    if ($Signature.Status -ne "Valid") {
        throw "Signature verification FAILED. Status: $($Signature.Status). Binary cannot be released as signed."
    }

    $finalHash = (Get-FileHash $ResolvedExe.Path -Algorithm SHA256).Hash.ToLower()
    Write-Host "      Final SHA-256 Checksum: $finalHash" -ForegroundColor Yellow

    Write-Host "====================================================" -ForegroundColor Green
    Write-Host " AUTHENTICODE SIGNATURE VERIFIED: PRODUCTION READY" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Green
    exit 0
}
finally {
    if ($tempPfxCreated -and (Test-Path $tempPfxCreated)) {
        Remove-Item -Path $tempPfxCreated -Force -ErrorAction SilentlyContinue
    }
}
