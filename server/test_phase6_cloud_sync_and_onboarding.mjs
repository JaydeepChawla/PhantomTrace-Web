/**
 * =====================================================================
 * PHANTOMTRACE PHASE 6: CLOUD SYNCHRONIZATION & ONBOARDING TEST SUITE
 * =====================================================================
 * Validates:
 * 1. Windows Scan Upload Authentication & Scoped Device Tokens
 * 2. Duplicate Scan Idempotency & Conflict Handling
 * 3. Browser Threat Event Ingestion & Stable Deduplication
 * 4. Tenant Isolation across Multiple Users
 * 5. Input Validation, Sanitization, and Error Boundaries
 * 6. Health & Database Connectivity Separation
 * 7. Frontend & Extension Bundle Secrets Leak Checks
 * =====================================================================
 */

import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 5096;
process.env.PORT = String(PORT);
process.env.NODE_ENV = "test";
process.env.PHANTOMTRACE_API_KEY = "test-master-owner-key-phase6";

let server;
let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`[PASS] ✓ ${message}`);
    passCount++;
  } else {
    console.error(`[FAIL] ✗ ${message}`);
    failCount++;
  }
}

async function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: PORT,
        path,
        method: options.method || "GET",
        headers: options.headers || {},
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          let data = null;
          try {
            data = JSON.parse(body);
          } catch {
            data = body;
          }
          resolve({ status: res.statusCode, headers: res.headers, data });
        });
      }
    );
    req.on("error", reject);
    if (options.body) {
      req.write(typeof options.body === "string" ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

async function runTests() {
  console.log("\n=======================================================");
  console.log("  PHANTOMTRACE PHASE 6: CLOUD SYNC & ONBOARDING TESTS   ");
  console.log("=======================================================\n");

  // 1. Health & Database Check Separation
  const healthRes = await request("/api/health");
  assert(healthRes.status === 200 || healthRes.status === 503, "GET /api/health responds with valid HTTP status");
  assert(healthRes.data && healthRes.data.service === "PhantomTrace API", "Health reports service name accurately");
  assert("databaseConnected" in healthRes.data, "Health endpoint separates database connectivity from service health");

  // 2. Auth Session Creation for Tenant A
  const sessionResA = await request("/api/auth/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: { displayName: "Analyst A" },
  });
  assert(sessionResA.status === 200, "Session A created (200)");
  const tokenA = sessionResA.data.sessionToken;
  const uidA = sessionResA.data.user.uid;

  // Session Creation for Tenant B
  const sessionResB = await request("/api/auth/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: { displayName: "Analyst B" },
  });
  assert(sessionResB.status === 200, "Session B created (200)");
  const tokenB = sessionResB.data.sessionToken;
  const uidB = sessionResB.data.user.uid;
  assert(uidA !== uidB, "Tenant A and Tenant B have distinct isolated UIDs");

  // 3. Device Pairing for Tenant A
  const pairStart = await request("/api/devices/pair/start", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenA}`,
      "Content-Type": "application/json",
    },
    body: { deviceName: "DESKTOP-PHASE6-PC" },
  });
  assert(pairStart.status === 200, "Tenant A started device pairing (200)");
  const pairingCode = pairStart.data.pairingCode;

  // Redeem pairing code to get scoped device credential (pt_dev_)
  const redeemRes = await request("/api/devices/pair/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: { pairingCode, deviceName: "DESKTOP-PHASE6-PC" },
  });
  assert(redeemRes.status === 200, "Device paired successfully (200)");
  const devTokenA = redeemRes.data.deviceToken;
  assert(Boolean(devTokenA && devTokenA.startsWith("pt_dev_")), "Scoped device token has 'pt_dev_' prefix");

  // 4. Windows Scan Upload Authentication Tests
  const validScanPayload = {
    scan_id: "scan-phase6-test-01",
    timestamp: new Date().toISOString(),
    platform: "Windows 11 Pro 64-bit",
    processes: [
      {
        pid: 1024,
        name: "svchost.exe",
        path: "C:\\Windows\\System32\\svchost.exe",
        threat_score: 15,
        threat_level: "NORMAL",
        score_mode: "NONE",
      },
      {
        pid: 2048,
        name: "suspicious_payload.exe",
        path: "C:\\Users\\User\\AppData\\Local\\Temp\\suspicious_payload.exe",
        threat_score: 88,
        threat_level: "CRITICAL",
        score_mode: "MEMORY",
        memory_evidence: {
          present: true,
          indicators: ["Unbacked executable memory detected in PAGE_EXECUTE_READWRITE allocation."],
        },
      },
    ],
  };

  // Upload without token
  const unauthUpload = await request("/api/scans/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: validScanPayload,
  });
  assert(unauthUpload.status === 401, "Unauthenticated scan upload rejected (401)");

  // Upload with invalid token
  const badTokenUpload = await request("/api/scans/ingest", {
    method: "POST",
    headers: {
      Authorization: "Bearer invalid-garbage-token",
      "Content-Type": "application/json",
    },
    body: validScanPayload,
  });
  assert(badTokenUpload.status === 401, "Malformed token scan upload rejected (401)");

  // Upload with scoped device token
  const devUpload = await request("/api/scans/ingest", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${devTokenA}`,
      "Content-Type": "application/json",
    },
    body: validScanPayload,
  });
  assert(devUpload.status === 201, "Scoped Windows Agent upload accepted (201 Created)");
  assert(devUpload.data.scanId === "scan-phase6-test-01", "Returned scanId matches payload scanId");
  assert(devUpload.data.processesImported === 2, "2 processes imported");
  assert(devUpload.data.highestScore === 88, "Highest score 88 imported");

  // 5. Duplicate Scan Prevention & Idempotency
  const dupUpload = await request("/api/scans/ingest", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${devTokenA}`,
      "Content-Type": "application/json",
    },
    body: validScanPayload,
  });
  assert(dupUpload.status === 200, "Duplicate scan accepted idempotently with HTTP 200");
  assert(dupUpload.data.duplicate === true, "Response confirms duplicate: true flag");
  assert(dupUpload.data.scanId === "scan-phase6-test-01", "Existing scan record reused");

  // 6. Tenant Isolation on Scans
  const scansA = await request("/api/scans", {
    headers: { Authorization: `Bearer ${tokenA}` },
  });
  assert(scansA.status === 200, "Tenant A can list scans (200)");
  assert(scansA.data.scans.some((s) => s.scanId === "scan-phase6-test-01"), "Tenant A sees uploaded scan");

  const scansB = await request("/api/scans", {
    headers: { Authorization: `Bearer ${tokenB}` },
  });
  assert(scansB.status === 200, "Tenant B can list scans (200)");
  assert(
    !scansB.data.scans.some((s) => s.scanId === "scan-phase6-test-01"),
    "Tenant B CANNOT see Tenant A's scan (strict tenant isolation enforced)"
  );

  // 7. Browser Web Threat Event Ingestion
  const sanitizedThreatEvent = {
    id: "wte-ext-loginverify-phish-01",
    domain: "login-verify-account.com",
    url: "https://login-verify-account.com/auth",
    classification: "PHISHING",
    severity: "HIGH",
    score: 85,
    confidence: "HIGH",
    detectionSource: "THREAT_INTEL",
    ruleId: "PHISH-HEURISTIC-101",
    explanation: "Suspicious credential phishing domain detected.",
    browser: "Chrome/Edge Manifest V3",
  };

  const threatIngestRes = await request("/api/web-threats/events", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenA}`,
      "Content-Type": "application/json",
    },
    body: sanitizedThreatEvent,
  });
  assert(threatIngestRes.status === 201, "Browser web threat event ingested (201 Created)");
  assert(threatIngestRes.data.eventId === "wte-ext-loginverify-phish-01", "Event ID preserved idempotently");

  // Duplicate web threat event idempotency
  const dupThreatRes = await request("/api/web-threats/events", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenA}`,
      "Content-Type": "application/json",
    },
    body: sanitizedThreatEvent,
  });
  assert(dupThreatRes.status === 201, "Duplicate web threat event handled cleanly without error");

  // Tenant Isolation on Web Threat Events
  const eventsA = await request("/api/web-threats/events", {
    headers: { Authorization: `Bearer ${tokenA}` },
  });
  assert(eventsA.status === 200, "Tenant A lists web threat events (200)");
  assert(
    eventsA.data.events.some((e) => e.domain === "login-verify-account.com"),
    "Tenant A sees browser threat event"
  );

  const eventsB = await request("/api/web-threats/events", {
    headers: { Authorization: `Bearer ${tokenB}` },
  });
  assert(
    !eventsB.data.events.some((e) => e.domain === "login-verify-account.com"),
    "Tenant B CANNOT see Tenant A's web threat events (strict isolation)"
  );

  // 8. Payload Validation Boundaries
  const emptyScanRes = await request("/api/scans/ingest", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenA}`,
      "Content-Type": "application/json",
    },
    body: {},
  });
  assert(emptyScanRes.status === 400, "Empty scan payload rejected (400 INVALID_SCAN)");

  const invalidDomainRes = await request("/api/web-threats/events", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenA}`,
      "Content-Type": "application/json",
    },
    body: { domain: "invalid :// url domain" },
  });
  assert(invalidDomainRes.status === 400, "Malformed web threat URL rejected (400 MALFORMED_URL)");

  // 9. Secrets Leakage Audit in Built Bundles
  console.log("\nAuditing frontend & extension bundles for credential leakage...");
  const distDir = path.resolve(__dirname, "../dist/assets");
  let bundlesChecked = 0;
  let leakFound = false;

  if (fs.existsSync(distDir)) {
    const files = fs.readdirSync(distDir).filter((f) => f.endsWith(".js"));
    for (const f of files) {
      bundlesChecked++;
      const content = fs.readFileSync(path.join(distDir, f), "utf8");
      if (content.includes("test-master-owner-key") || content.includes("postgresql://") || content.includes("postgres://")) {
        leakFound = true;
      }
    }
  }

  const extDir = path.resolve(__dirname, "../browser-extension");
  if (fs.existsSync(extDir)) {
    const extFiles = ["background.js", "popup.js", "warning.js"];
    for (const f of extFiles) {
      const p = path.join(extDir, f);
      if (fs.existsSync(p)) {
        bundlesChecked++;
        const content = fs.readFileSync(p, "utf8");
        if (content.includes("test-master-owner-key") || content.includes("postgresql://") || content.includes("postgres://")) {
          leakFound = true;
        }
      }
    }
  }

  assert(!leakFound, "No secret keys or database connection strings leaked in client bundles");
  assert(bundlesChecked > 0, `Audited ${bundlesChecked} bundle files successfully`);

  console.log("\n=======================================================");
  console.log(`  PHASE 6 TEST SUMMARY: PASSED: ${passCount} | FAILED: ${failCount}`);
  console.log("=======================================================\n");

  server.close();
  process.exit(failCount === 0 ? 0 : 1);
}

// Start test server
import { app } from "./dist/app.js";
server = app.listen(PORT, "127.0.0.1", () => {
  runTests().catch((err) => {
    console.error("Test execution error:", err);
    server.close();
    process.exit(1);
  });
});
