#!/usr/bin/env node
/**
 * PhantomTrace Release Consistency & Checksum Verification Script
 *
 * Implements strict release integrity verification:
 *   1. Confirm installer, checksum manifest, and metadata exist
 *   2. Recalculate SHA-256 from the actual installer file on disk
 *   3. Compare the actual hash with the checksum manifest
 *   4. Compare the actual hash with release metadata
 *   5. Validate the release version and filename
 *   6. Validate metadata signature contract (Production Signed, Development/Internal-Testing, or Unsigned)
 *   7. On Windows, verify Authenticode signature matches declared metadata
 *   8. Reject missing files, empty installers, invalid hashes, malformed metadata, or mismatched versions/signatures
 *
 * Notice: A SHA-256 match establishes file integrity against the supplied checksum;
 * it does not prove publisher identity for unsigned releases.
 */

import child_process from "child_process";
import crypto from "crypto";
import fs from "fs";
import https from "https";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

export const SEMVER_REGEX = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/**
 * Independently hashes a file on disk using SHA-256.
 */
export function hashFile(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const buffer = fs.readFileSync(filePath);
  const hash = crypto.createHash("sha256").update(buffer).digest("hex").toLowerCase();
  return {
    path: filePath,
    sizeBytes: buffer.length,
    sha256: hash,
  };
}

/**
 * Verifies a release artifact directory against the strict 8-step unsigned release integrity specification.
 *
 * @param {string} targetDirPath - Directory containing PhantomTrace_Agent_Setup.exe, .sha256, and release_metadata.json
 * @param {object} [options]
 * @returns {{ ok: boolean, errors: string[], diskHash?: string, sizeBytes?: number, version?: string, meta?: any }}
 */
export function verifyReleaseDirectory(targetDirPath, options = {}) {
  const resolvedDir = path.resolve(rootDir, targetDirPath);
  const errors = [];

  const installerPath = path.join(resolvedDir, "PhantomTrace_Agent_Setup.exe");
  const manifestPath = path.join(resolvedDir, "PhantomTrace_Agent_Setup.exe.sha256");
  const metadataPath = path.join(resolvedDir, "release_metadata.json");

  // Step 1: Confirm installer, checksum manifest, and metadata exist
  const installerExists = fs.existsSync(installerPath);
  const manifestExists = fs.existsSync(manifestPath);
  const metadataExists = fs.existsSync(metadataPath);

  if (!installerExists) {
    errors.push(`Missing installer artifact: ${installerPath}`);
  }
  if (!manifestExists) {
    errors.push(`Missing checksum manifest artifact: ${manifestPath}`);
  }
  if (!metadataExists) {
    errors.push(`Missing release metadata artifact: ${metadataPath}`);
  }

  if (errors.length > 0) {
    return { ok: false, errors, dir: resolvedDir };
  }

  // Step 2: Reject empty installers and recalculate SHA-256 from actual installer file on disk
  const installerStat = fs.statSync(installerPath);
  if (installerStat.size === 0) {
    errors.push(`Empty installer executable (0 bytes): ${installerPath}`);
    return { ok: false, errors, dir: resolvedDir };
  }

  const installerHashObj = hashFile(installerPath);
  if (!installerHashObj || !installerHashObj.sha256) {
    errors.push(`Failed to calculate SHA-256 for installer file: ${installerPath}`);
    return { ok: false, errors, dir: resolvedDir };
  }
  const diskHash = installerHashObj.sha256;

  // Step 3: Compare actual hash with the checksum manifest
  const rawManifest = fs.readFileSync(manifestPath, "utf-8").trim();
  const manifestMatch = rawManifest.match(/^([a-fA-F0-9]{64})/);
  if (!manifestMatch) {
    errors.push(`Malformed checksum manifest in ${manifestPath}. Expected 64-hex SHA-256 checksum.`);
  } else {
    const manifestHash = manifestMatch[1].toLowerCase();
    if (diskHash !== manifestHash) {
      errors.push(`Checksum manifest mismatch: Disk hash (${diskHash}) !== Manifest hash (${manifestHash})`);
    }
  }

  // Step 4 & 5 & 6: Parse release metadata, validate filename, version, and unsigned policy
  let meta = null;
  try {
    meta = JSON.parse(fs.readFileSync(metadataPath, "utf-8"));
  } catch (e) {
    errors.push(`Malformed metadata JSON in ${metadataPath}: ${e.message}`);
    return { ok: false, errors, dir: resolvedDir, diskHash };
  }

  // Compare actual hash with release metadata
  if (!meta.sha256) {
    errors.push(`Metadata is missing required 'sha256' field in ${metadataPath}`);
  } else if (meta.sha256.toLowerCase() !== diskHash) {
    errors.push(`Metadata SHA-256 mismatch: Disk hash (${diskHash}) !== Metadata sha256 (${meta.sha256.toLowerCase()})`);
  }

  // Validate filename
  if (!meta.filename) {
    errors.push(`Metadata is missing required 'filename' field in ${metadataPath}`);
  } else if (meta.filename !== "PhantomTrace_Agent_Setup.exe") {
    errors.push(`Metadata filename mismatch: Expected 'PhantomTrace_Agent_Setup.exe', got '${meta.filename}'`);
  }

  // Validate version strictly with Semantic Versioning
  if (!meta.version) {
    errors.push(`Metadata is missing required 'version' field in ${metadataPath}`);
  } else if (!SEMVER_REGEX.test(meta.version)) {
    errors.push(`Metadata version '${meta.version}' does not match Semantic Versioning (expected vMAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH).`);
  }

  // Step 6: Validate metadata signature contract
  const VALID_SIGNATURE_STATUSES = ["Signed", "Development/Internal-Testing", "Unsigned"];

  if (typeof meta.isProductionSigned !== "boolean") {
    errors.push(`Metadata isProductionSigned must be a boolean (got '${meta.isProductionSigned}').`);
  }

  if (!VALID_SIGNATURE_STATUSES.includes(meta.signatureStatus)) {
    errors.push(`Unknown metadata signatureStatus '${meta.signatureStatus}'. Expected one of: ${VALID_SIGNATURE_STATUSES.join(", ")}.`);
  }

  const isPublisherValid = typeof meta.publisher === "string" && meta.publisher.trim().length > 0;

  if (meta.signatureStatus === "Signed") {
    if (meta.isProductionSigned !== true) {
      errors.push(`Metadata signatureStatus 'Signed' requires isProductionSigned=true (got '${meta.isProductionSigned}').`);
    }
    if (!isPublisherValid) {
      errors.push(`Metadata publisher must be a valid non-empty string when signatureStatus is 'Signed' (got '${meta.publisher}').`);
    }
  } else if (meta.signatureStatus === "Development/Internal-Testing") {
    if (meta.isProductionSigned !== false) {
      errors.push(`Metadata signatureStatus 'Development/Internal-Testing' requires isProductionSigned=false (got '${meta.isProductionSigned}').`);
    }
    if (!isPublisherValid) {
      errors.push(`Metadata publisher must be a valid non-empty string when signatureStatus is 'Development/Internal-Testing' (got '${meta.publisher}').`);
    }
  } else if (meta.signatureStatus === "Unsigned") {
    if (meta.isProductionSigned !== false) {
      errors.push(`Metadata signatureStatus 'Unsigned' requires isProductionSigned=false (got '${meta.isProductionSigned}').`);
    }
    if (meta.publisher !== null) {
      errors.push(`Metadata publisher must be null when signatureStatus is 'Unsigned' (got '${meta.publisher}').`);
    }
  }

  // Step 7: On Windows, verify disk Authenticode signature matches declared metadata
  let sig = options.signatureInfo || null;
  if (!sig && process.env.MOCK_AUTHENTICODE_SIGNATURE) {
    try {
      sig = JSON.parse(process.env.MOCK_AUTHENTICODE_SIGNATURE);
    } catch {
      sig = null;
    }
  }

  if (!sig && process.platform === "win32") {
    try {
      const psScript = `
$ProgressPreference = 'SilentlyContinue'
$targetPath = '${installerPath.replace(/'/g, "''")}'
$sig = Get-AuthenticodeSignature -LiteralPath $targetPath
$status = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }
$msg = if ($sig) { $sig.StatusMessage } else { '' }
$cert = if ($sig) { $sig.SignerCertificate } else { $null }
$subject = if ($cert) { $cert.Subject } else { '' }
$issuer = if ($cert) { $cert.Issuer } else { '' }
$thumbprint = if ($cert) { $cert.Thumbprint } else { '' }
$isSelfSigned = $false
$isDevCert = $false

if ($cert) {
    if ($cert.Subject.Trim() -eq $cert.Issuer.Trim()) {
        $isSelfSigned = $true
    }
    $devPattern = "(?i)\\b(dev|development|test|testing|staging|demo|sample|example|self-?signed|localhost|powershell)\\b"
    if ($cert.Subject -match $devPattern -or $cert.Issuer -match $devPattern -or ($cert.FriendlyName -and $cert.FriendlyName -match $devPattern)) {
        $isDevCert = $true
    }
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        if ($chain.Build($cert)) {
            if ($chain.ChainElements.Count -le 1) {
                $isSelfSigned = $true
            } else {
                $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
                if ($rootCert.Thumbprint -eq $cert.Thumbprint) {
                    $isSelfSigned = $true
                }
            }
            foreach ($el in $chain.ChainElements) {
                if ($el.Certificate -and ($el.Certificate.Subject -match $devPattern -or $el.Certificate.Issuer -match $devPattern)) {
                    $isDevCert = $true
                    break
                }
            }
        }
    } catch {}
}

[PSCustomObject]@{
    Status = $status
    StatusMessage = $msg
    Subject = $subject
    Issuer = $issuer
    Thumbprint = $thumbprint
    IsSelfSigned = $isSelfSigned
    IsDevCert = $isDevCert
} | ConvertTo-Json -Compress
`;

      const encoded = Buffer.from(psScript, "utf16le").toString("base64");
      const raw = child_process.execFileSync("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded
      ], { encoding: "utf-8" }).trim();
      const jsonStart = raw.indexOf("{");
      const jsonEnd = raw.lastIndexOf("}");
      if (jsonStart !== -1 && jsonEnd !== -1) {
        sig = JSON.parse(raw.slice(jsonStart, jsonEnd + 1));
      } else {
        errors.push(`Failed to parse Authenticode signature output from PowerShell.`);
      }
    } catch (err) {
      errors.push(`Authenticode inspection failed: ${err.message || String(err)}`);
    }
  }

  if (sig) {
    const isDev = Boolean(sig.IsDevCert || sig.IsSelfSigned || sig.isDevCert || sig.isSelfSigned);
    const thumbprint = (sig.Thumbprint || sig.thumbprint || "").replace(/[\s:-]/g, "").toUpperCase();
    const allowlistEnv = process.env.PRODUCTION_CERT_THUMBPRINTS || process.env.PRODUCTION_CERT_THUMBPRINT || "";
    const allowlist = (options.productionThumbprints || (allowlistEnv ? allowlistEnv.split(/[,;\s]+/) : []))
      .filter(Boolean)
      .map((t) => t.replace(/[\s:-]/g, "").toUpperCase());

    if (sig.Status === "Valid") {
      if (meta.signatureStatus === "Unsigned") {
        errors.push(`Signature mismatch: Binary on disk has valid Authenticode signature (${sig.Subject || "Unknown"}), but metadata declares signatureStatus is 'Unsigned'.`);
      } else if (meta.signatureStatus === "Signed" && meta.isProductionSigned === true) {
        if (isDev) {
          errors.push(`Signature mismatch: Binary on disk has development/self-signed Authenticode signature (${sig.Subject || "Unknown"}), but metadata declares production approval (isProductionSigned=true).`);
        } else if (allowlist.length > 0 && (!thumbprint || !allowlist.includes(thumbprint))) {
          errors.push(`Signature mismatch: Binary signing certificate (${thumbprint || "none"}) is not in the production certificate allowlist.`);
        }
      }
    } else if (sig.Status === "NotSigned") {
      if (meta.signatureStatus === "Signed" || meta.signatureStatus === "Development/Internal-Testing" || meta.isProductionSigned === true) {
        errors.push(`Signature mismatch: Metadata claims ${meta.signatureStatus} artifact (${meta.publisher || "declared publisher"}), but binary on disk is NotSigned.`);
      }
    } else {
      // Other signature statuses (e.g. HashMismatch, NotTrusted, UnknownError, Incompatible, etc.)
      if (meta.signatureStatus === "Signed" || meta.signatureStatus === "Development/Internal-Testing" || meta.isProductionSigned === true) {
        errors.push(`Signature verification failed: Binary on disk does not have a valid Authenticode signature (status: '${sig.Status}', ${sig.StatusMessage || "signature verification failed"}).`);
      } else if (sig.Status === "HashMismatch" || sig.Status === "NotTrusted" || sig.Subject) {
        errors.push(`Signature mismatch: Binary on disk has signature status '${sig.Status}' (${sig.StatusMessage || ""}), but metadata claims 'Unsigned'.`);
      } else {
        errors.push(`Signature verification error: Binary on disk returned signature status '${sig.Status}' (${sig.StatusMessage || "verification error"}).`);
      }
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    dir: resolvedDir,
    diskHash,
    sizeBytes: installerStat.size,
    version: meta ? meta.version : undefined,
    meta,
  };
}

/**
 * Downloads and hashes a stream from a URL (used for live endpoint checks).
 */
async function hashStream(url) {
  return new Promise((resolve) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(hashStream(res.headers.location));
      }
      if (res.statusCode !== 200) {
        return resolve({
          url,
          status: res.statusCode,
          ok: false,
          error: `HTTP ${res.statusCode}`,
        });
      }
      const hash = crypto.createHash("sha256");
      let totalBytes = 0;
      res.on("data", (chunk) => {
        totalBytes += chunk.length;
        hash.update(chunk);
      });
      res.on("end", () => {
        resolve({
          url,
          status: res.statusCode,
          ok: true,
          sizeBytes: totalBytes,
          sha256: hash.digest("hex").toLowerCase(),
          contentDisposition: res.headers["content-disposition"] || "",
          contentType: res.headers["content-type"] || "",
        });
      });
      res.on("error", (err) => resolve({ url, ok: false, error: err.message }));
    });
    req.on("error", (err) => resolve({ url, ok: false, error: err.message }));
    req.setTimeout(30000, () => {
      req.destroy();
      resolve({ url, ok: false, error: "Connection timed out (30s)" });
    });
  });
}

/**
 * Inspects Authenticode signature status purely for informational reporting without enforcing any signature requirements.
 */
async function reportAuthenticodeStatus(filePath, meta = null) {
  if (process.platform !== "win32") return;
  try {
    const { execSync } = await import("child_process");
    const escapedPath = filePath.replace(/'/g, "''");
    const sigRaw = execSync(
      `powershell -NoProfile -Command "$sig = Get-AuthenticodeSignature -LiteralPath '${escapedPath}'; [PSCustomObject]@{ Status = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }; Subject = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' } } | ConvertTo-Json"`,
      { encoding: "utf-8" }
    );
    const sig = JSON.parse(sigRaw);
    console.log(`[SIGNATURE INFO] Authenticode status on disk: ${sig.Status}`);
    if (meta?.signatureStatus === "Signed") {
      console.log(`                 Policy: Production-Approved Signed Release.`);
      console.log(`                 Publisher: ${meta.publisher}\n`);
    } else if (meta?.signatureStatus === "Development/Internal-Testing") {
      console.log(`                 Policy: Development/Internal-Testing Signature.`);
      console.log(`                 Publisher: ${meta.publisher}\n`);
    } else {
      console.log(`                 Policy: Explicitly Unsigned. No Authenticode certificate required.`);
      console.log(`                 Notice: SHA-256 match establishes file integrity against the supplied checksum;`);
      console.log(`                         it does not prove publisher identity.\n`);
    }
  } catch {
    // Non-fatal inspection
  }
}

/**
 * Main consistency checking CLI routine.
 */
export async function runConsistencyCheck() {
  console.log("================================================================================");
  console.log(" PHANTOMTRACE RELEASE INTEGRITY & CONSISTENCY VERIFICATION");
  console.log("================================================================================\n");

  const results = [];
  let totalFailures = 0;

  // Check if a specific target directory was passed via CLI argument
  const customTarget = process.argv[2];
  if (customTarget && !customTarget.startsWith("-")) {
    console.log(`[TARGET] Verifying explicitly requested directory: ${customTarget}`);
    const check = verifyReleaseDirectory(customTarget);
    if (!check.ok) {
      console.error(`\n❌ Verification failed for '${customTarget}':`);
      for (const err of check.errors) {
        console.error(`   - ${err}`);
      }
      process.exit(1);
    }
    console.log(`✅ Verification passed for '${customTarget}':`);
    console.log(`   SHA-256: ${check.diskHash}`);
    console.log(`   Size:    ${check.sizeBytes} bytes`);
    console.log(`   Version: ${check.version}`);
    if (check.meta?.signatureStatus === "Signed") {
      console.log(`   Status:  Production-approved (Signed, Publisher: ${check.meta.publisher})\n`);
    } else if (check.meta?.signatureStatus === "Development/Internal-Testing") {
      console.log(`   Status:  Development/Internal-Testing (Publisher: ${check.meta.publisher})\n`);
    } else {
      console.log(`   Status:  Explicitly Unsigned (integrity verified by SHA-256)\n`);
    }
    process.exit(0);
  }

  // Determine directories to verify
  const distDir = path.join(rootDir, "dist");
  const publicDir = path.join(rootDir, "public/downloads");

  let verifiedAny = false;

  // 1. Verify dist/ if release artifacts are present in dist/
  if (fs.existsSync(path.join(distDir, "release_metadata.json")) || fs.existsSync(path.join(distDir, "PhantomTrace_Agent_Setup.exe.sha256"))) {
    console.log(`[VERIFY] Checking build staging release artifacts in dist/...`);
    const distCheck = verifyReleaseDirectory("dist");
    if (distCheck.ok) {
      console.log(`[DIST OK] Staged release artifacts in dist/ verified:`);
      console.log(`          Version: ${distCheck.version}`);
      console.log(`          SHA-256: ${distCheck.diskHash}`);
      console.log(`          Size:    ${distCheck.sizeBytes} bytes\n`);
      results.push({
        target: "Build Staging (dist/)",
        status: `Verified ${distCheck.meta?.signatureStatus || "Release"}`,
        sizeBytes: distCheck.sizeBytes,
        sha256: distCheck.diskHash,
      });
      verifiedAny = true;
    } else {
      console.error(`[DIST ERROR] Staged release artifacts in dist/ failed integrity check:`);
      for (const err of distCheck.errors) {
        console.error(`   - ${err}`);
        totalFailures++;
      }
      console.log("");
    }
  }

  // 2. Verify public/downloads/ if present
  if (fs.existsSync(publicDir)) {
    console.log(`[VERIFY] Checking repository public download artifacts in public/downloads/...`);
    const publicCheck = verifyReleaseDirectory("public/downloads");
    if (publicCheck.ok) {
      console.log(`[PUBLIC OK] Public download artifacts in public/downloads/ verified:`);
      console.log(`            Version: ${publicCheck.version}`);
      console.log(`            SHA-256: ${publicCheck.diskHash}`);
      console.log(`            Size:    ${publicCheck.sizeBytes} bytes\n`);
      results.push({
        target: "Local Working Repo (public/downloads)",
        status: `Verified ${publicCheck.meta?.signatureStatus || "Release"}`,
        sizeBytes: publicCheck.sizeBytes,
        sha256: publicCheck.diskHash,
      });
      verifiedAny = true;

      await reportAuthenticodeStatus(path.join(publicDir, "PhantomTrace_Agent_Setup.exe"), publicCheck.meta);
    } else {
      console.error(`[PUBLIC ERROR] Public download artifacts in public/downloads/ failed integrity check:`);
      for (const err of publicCheck.errors) {
        console.error(`   - ${err}`);
        totalFailures++;
      }
      console.log("");
    }
  }

  if (!verifiedAny && totalFailures === 0) {
    console.error("❌ CRITICAL: No release artifacts found in dist/ or public/downloads/ to verify.");
    process.exit(1);
  }

  // 3. Inspect Live Endpoints
  const endpoints = [
    {
      name: "Vercel Production Static",
      url: "https://phantom-trace-web.vercel.app/downloads/PhantomTrace_Agent_Setup.exe",
      expectedFilename: "PhantomTrace_Agent_Setup.exe",
    },
    {
      name: "Render Backend API",
      url: "https://phantomtrace-web.onrender.com/api/agent/download?installer=true",
      expectedFilename: "PhantomTrace_Agent_Setup.exe",
    },
  ];

  for (const ep of endpoints) {
    process.stdout.write(`Fetching ${ep.name} (${ep.url})...\n`);
    const res = await hashStream(ep.url);
    if (res.ok) {
      results.push({
        target: ep.name,
        status: `HTTP ${res.status}`,
        sizeBytes: res.sizeBytes,
        sha256: res.sha256,
      });
    } else {
      results.push({
        target: ep.name,
        status: res.status ? `HTTP ${res.status}` : "FAILED",
        error: res.error,
      });
    }
  }

  // 4. Output Summary Table
  console.log("\n--------------------------------------------------------------------------------");
  console.log(" ARTIFACT VERIFICATION SUMMARY");
  console.log("--------------------------------------------------------------------------------");
  console.log(
    "Target".padEnd(38) +
    "Status".padEnd(20) +
    "Size (Bytes)".padEnd(16) +
    "SHA-256 Checksum"
  );
  console.log("-".repeat(110));

  for (const r of results) {
    if (r.sha256) {
      console.log(
        r.target.padEnd(38) +
        r.status.padEnd(20) +
        r.sizeBytes.toString().padEnd(16) +
        r.sha256
      );
    } else {
      console.log(
        r.target.padEnd(38) +
        (r.status || "ERR").padEnd(20) +
        "-".padEnd(16) +
        `[${r.error || "Unavailable"}]`
      );
    }
  }
  console.log("--------------------------------------------------------------------------------\n");

  // 5. Cross-Comparison Consistency Assertions
  const vercelResult = results.find((r) => r.target === "Vercel Production Static");
  const renderResult = results.find((r) => r.target === "Render Backend API");

  if (vercelResult?.sha256 && renderResult?.sha256) {
    if (vercelResult.sha256 === renderResult.sha256) {
      console.log("✅ Vercel and Render endpoints serve byte-for-byte identical binaries!");
    } else {
      console.error("❌ Mismatch detected between Vercel and Render downloads!");
      totalFailures++;
    }
  }

  if (totalFailures > 0) {
    console.error(`\n❌ Integrity verification finished with ${totalFailures} failure(s).`);
    process.exit(1);
  }

  console.log("\n✅ All release integrity and consistency checks completed successfully.");
}

// Execute when run directly as CLI
const isDirectRun = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isDirectRun) {
  runConsistencyCheck().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}
