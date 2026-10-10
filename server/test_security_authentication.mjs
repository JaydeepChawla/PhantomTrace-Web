/**
 * =====================================================================
 * PHANTOMTRACE SECURITY REGRESSION TEST SUITE: AUTHENTICATION & AUTHORIZATION
 * =====================================================================
 * Validates critical security constraints:
 * 1. Anonymous request cannot impersonate 'phantomtrace-owner' via session creation.
 * 2. Client cannot hijack or impersonate another tenant's UID.
 * 3. Missing, malformed, invalid, and nonexistent credentials are strictly rejected (401).
 * 4. Protected endpoints derive authorized identity strictly from verified credentials.
 * 5. Authenticated administrative sign-in (/api/auth/login) requires valid master API key.
 * 6. Legitimate Windows Agent pairing, scoped credential issuance, scan upload, and revocation.
 * =====================================================================
 */

import http from "http";
import { app } from "./dist/app.js";

async function runSecurityTests() {
  console.log("=======================================================");
  console.log("  PHANTOMTRACE CRITICAL SECURITY REGRESSION TEST SUITE ");
  console.log("=======================================================");

  let passed = 0;
  let failed = 0;

  function assert(condition, desc) {
    if (condition) {
      console.log(`[PASS] ✓ ${desc}`);
      passed++;
    } else {
      console.error(`[FAIL] ✗ ${desc}`);
      failed++;
    }
  }

  // Set test master API key
  const testMasterApiKey = "test-master-owner-key-1234567890abcdef";
  process.env.PHANTOMTRACE_API_KEY = testMasterApiKey;
  process.env.PHANTOMTRACE_OWNER_UID = "phantomtrace-owner";

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // -----------------------------------------------------------------
    // 1. Prevention of Impersonation of 'phantomtrace-owner' on Public Session Creation
    // -----------------------------------------------------------------
    let tokenAttacker;
    let attackerUid;
    {
      const res = await fetch(`${baseUrl}/api/auth/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          displayName: "Malicious Attacker",
          uid: "phantomtrace-owner", // Attempting to claim owner UID
        }),
      });
      assert(res.status === 200, "POST /api/auth/session succeeds for guest");
      const data = await res.json();
      tokenAttacker = data.sessionToken;
      attackerUid = data.user.uid;

      assert(attackerUid !== "phantomtrace-owner", "Session UID is NOT 'phantomtrace-owner'");
      assert(attackerUid.startsWith("usr_"), "Session UID is randomly generated with 'usr_' prefix");
      assert(attackerUid.length >= 36, "Session UID has strong cryptographic entropy (128-bit)");

      // Attempt to access owner's endpoints using the attacker's guest token
      const resScans = await fetch(`${baseUrl}/api/scans`, {
        headers: { Authorization: `Bearer ${tokenAttacker}` },
      });
      assert(resScans.status === 200, "GET /api/scans returns 200 for authenticated guest");
      const scansData = await resScans.json();
      assert(Array.isArray(scansData.scans), "Scans returned as array");
      const hasOwnerScans = scansData.scans.some((s) => s.ownerUid === "phantomtrace-owner");
      assert(!hasOwnerScans, "Attacker cannot access records belonging to 'phantomtrace-owner'");
    }

    // -----------------------------------------------------------------
    // 2. Prevention of Cross-Tenant User UID Impersonation
    // -----------------------------------------------------------------
    let victimToken;
    let victimUid;
    {
      // Create Victim session
      const resVictim = await fetch(`${baseUrl}/api/auth/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ displayName: "Victim User" }),
      });
      const dataVictim = await resVictim.json();
      victimToken = dataVictim.sessionToken;
      victimUid = dataVictim.user.uid;

      // Attacker attempts to impersonate Victim by passing victim's UID
      const resImpersonate = await fetch(`${baseUrl}/api/auth/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          displayName: "Impersonator",
          uid: victimUid, // Attempting to hijack victim UID
        }),
      });
      const dataImpersonate = await resImpersonate.json();
      const impersonatorUid = dataImpersonate.user.uid;

      assert(impersonatorUid !== victimUid, "Attacker cannot hijack victim's UID via session initiation");
      assert(impersonatorUid !== attackerUid, "Every session initiation generates a distinct random UID");

      // Victim creates a domain policy
      const resCreatePolicy = await fetch(`${baseUrl}/api/web-threats/policies`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${victimToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          domain: "victim-private-domain.internal",
          policyType: "BLOCK",
          reason: "Victim restricted asset",
        }),
      });
      assert(resCreatePolicy.status === 201, "Victim creates tenant policy (201)");
      const policyData = await resCreatePolicy.json();
      const policyId = policyData.policy.policyId;

      // Impersonator attempts to delete victim's policy
      const resDeleteAttempt = await fetch(`${baseUrl}/api/web-threats/policies/${policyId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${dataImpersonate.sessionToken}` },
      });
      assert(resDeleteAttempt.status === 404, "Impersonator cannot delete victim's policy (isolated tenant)");

      // Impersonator lists policies
      const resListPolicies = await fetch(`${baseUrl}/api/web-threats/policies`, {
        headers: { Authorization: `Bearer ${dataImpersonate.sessionToken}` },
      });
      const listData = await resListPolicies.json();
      const seesVictimPolicy = listData.policies.some((p) => p.policyId === policyId);
      assert(!seesVictimPolicy, "Impersonator cannot view victim's policies");
    }

    // -----------------------------------------------------------------
    // 3. Rejection of Missing, Invalid, and Malformed Credentials
    // -----------------------------------------------------------------
    {
      // Missing header
      const resMissing = await fetch(`${baseUrl}/api/dashboard/overview`);
      assert(resMissing.status === 401, "Protected endpoint rejects missing Authorization header (401)");

      // Malformed header
      const resMalformed = await fetch(`${baseUrl}/api/dashboard/overview`, {
        headers: { Authorization: "NotABearerToken" },
      });
      assert(resMalformed.status === 401, "Protected endpoint rejects non-Bearer token (401)");

      // Empty Bearer token
      const resEmpty = await fetch(`${baseUrl}/api/dashboard/overview`, {
        headers: { Authorization: "Bearer " },
      });
      assert(resEmpty.status === 401, "Protected endpoint rejects empty Bearer token (401)");

      // Fake / Nonexistent User session token
      const resFakeUsr = await fetch(`${baseUrl}/api/dashboard/overview`, {
        headers: { Authorization: "Bearer pt_usr_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
      });
      assert(resFakeUsr.status === 401, "Protected endpoint rejects unverified pt_usr_ token (401)");

      // Fake / Nonexistent Device token
      const resFakeDev = await fetch(`${baseUrl}/api/dashboard/overview`, {
        headers: { Authorization: "Bearer pt_dev_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
      });
      assert(resFakeDev.status === 401, "Protected endpoint rejects unverified pt_dev_ token (401)");
    }

    // -----------------------------------------------------------------
    // 4. Strict Derivation of Identity from Credentials (No Request-Body Spoofing)
    // -----------------------------------------------------------------
    {
      // Call /devices/pair/start with Victim token, passing body { ownerUid: "phantomtrace-owner" }
      const resPair = await fetch(`${baseUrl}/api/devices/pair/start`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${victimToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ownerUid: "phantomtrace-owner", // Attempting body spoofing
        }),
      });
      assert(resPair.status === 200, "POST /devices/pair/start succeeds");
      const pairData = await resPair.json();
      const pairingId = pairData.pairingId;

      // Check status of pairing request
      const resStatus = await fetch(`${baseUrl}/api/devices/pair/status?pairingId=${pairingId}`, {
        headers: { Authorization: `Bearer ${victimToken}` },
      });
      assert(resStatus.status === 200, "GET /devices/pair/status succeeds for owner of pairing");

      // Attacker attempts to check victim's pairing status
      const resAttackerCheck = await fetch(`${baseUrl}/api/devices/pair/status?pairingId=${pairingId}`, {
        headers: { Authorization: `Bearer ${tokenAttacker}` },
      });
      assert(resAttackerCheck.status === 404, "Attacker cannot inspect victim's pairing request (404)");
    }

    // -----------------------------------------------------------------
    // 5. Genuine Authenticated Administrator Sign-In Flow (/api/auth/login)
    // -----------------------------------------------------------------
    let adminToken;
    {
      // Missing API key
      const resNoKey = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      assert(resNoKey.status === 401, "POST /api/auth/login rejects empty credentials (401)");

      // Wrong API key
      const resWrongKey = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: "wrong-password-attacker" }),
      });
      assert(resWrongKey.status === 401, "POST /api/auth/login rejects invalid API key (401)");

      // Correct Master API key
      const resValidKey = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: testMasterApiKey }),
      });
      assert(resValidKey.status === 200, "POST /api/auth/login succeeds with valid master key (200)");
      const validData = await resValidKey.json();
      adminToken = validData.sessionToken;
      assert(validData.user.uid === "phantomtrace-owner", "Admin session is bound to 'phantomtrace-owner'");
      assert(validData.user.role === "Administrator", "Admin session has role 'Administrator'");

      // Verify active session via /api/auth/me
      const resMe = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert(resMe.status === 200, "GET /api/auth/me succeeds for administrator");
      const meData = await resMe.json();
      assert(meData.user.uid === "phantomtrace-owner", "Session profile confirms 'phantomtrace-owner' identity");
    }

    // -----------------------------------------------------------------
    // 6. Legitimate Agent Pairing, Scoped Token Issuance, and Ingestion Flow
    // -----------------------------------------------------------------
    {
      // 1. Authenticated User A initiates pairing
      const resPairStart = await fetch(`${baseUrl}/api/devices/pair/start`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${victimToken}`,
          "Content-Type": "application/json",
        },
      });
      assert(resPairStart.status === 200, "User A starts device pairing");
      const pairStartData = await resPairStart.json();
      const code = pairStartData.pairingCode;
      const _pairingId = pairStartData.pairingId;

      // 2. Local Windows Agent submits pairing code to /pair/complete
      const resPairComplete = await fetch(`${baseUrl}/api/devices/pair/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairingCode: code,
          deviceName: "DESKTOP-SEC-NODE1",
          platform: "Windows 11 Pro (23H2)",
        }),
      });
      assert(resPairComplete.status === 200, "Agent completes pairing using one-time code (200)");
      const pairCompleteData = await resPairComplete.json();
      const deviceToken = pairCompleteData.deviceToken;
      const deviceId = pairCompleteData.deviceId;
      assert(deviceToken.startsWith("pt_dev_"), "Agent issued scoped 'pt_dev_' token");
      assert(pairCompleteData.ownerUid === victimUid, "Device correctly bound to User A's UID");

      // 3. Attempting to reuse pairing code fails (Single-use enforcement)
      const resReuse = await fetch(`${baseUrl}/api/devices/pair/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairingCode: code }),
      });
      assert(resReuse.status === 409, "Redeemed pairing code cannot be reused (409 Conflict)");

      // 4. Windows Agent uploads scan using scoped device token
      const scanPayload = {
        scanId: `scan-dev-${Date.now()}`,
        endpointId: deviceId,
        platform: "Windows (x86_64)",
        scannerVersion: "PhantomTrace Engine 1.0",
        timestamp: new Date().toISOString(),
        durationMs: 3200,
        totalProcesses: 4,
        highestScore: 78,
        memoryScanned: 8192,
        counts: { critical: 1, high: 0, medium: 1, low: 0, clean: 2 },
        processes: [
          {
            pid: 4096,
            name: "malicious_loader.exe",
            threatScore: 78,
            threatLevel: "CRITICAL",
            scoreMode: "CORRELATED",
            parentPid: 800,
          },
        ],
        alerts: [
          {
            id: `alert-dev-${Date.now()}`,
            pid: 4096,
            processName: "malicious_loader.exe",
            score: 78,
            level: "CRITICAL",
            scoreMode: "CORRELATED",
            detectedAt: new Date().toISOString(),
          },
        ],
      };

      const resIngest = await fetch(`${baseUrl}/api/scans/ingest`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${deviceToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(scanPayload),
      });
      assert(resIngest.status === 201 || resIngest.status === 200, "Agent uploads scan using scoped device credential (201 Created)");

      // 5. User A inspects scans and sees the uploaded scan
      const resUserScans = await fetch(`${baseUrl}/api/scans`, {
        headers: { Authorization: `Bearer ${victimToken}` },
      });
      const userScansData = await resUserScans.json();
      const hasUploadedScan = userScansData.scans.some((s) => s.scanId === scanPayload.scanId);
      assert(hasUploadedScan, "User A can see the scan uploaded by their paired Windows Agent");

      // 6. Attacker (User B) cannot see User A's scan
      const resAttackerScans = await fetch(`${baseUrl}/api/scans`, {
        headers: { Authorization: `Bearer ${tokenAttacker}` },
      });
      const attackerScansData = await resAttackerScans.json();
      const attackerSeesScan = attackerScansData.scans.some((s) => s.scanId === scanPayload.scanId);
      assert(!attackerSeesScan, "Attacker cannot see scans uploaded by User A's agent (tenant isolated)");

      // 7. User A revokes the device
      const resRevoke = await fetch(`${baseUrl}/api/devices/${deviceId}/revoke`, {
        method: "POST",
        headers: { Authorization: `Bearer ${victimToken}` },
      });
      assert(resRevoke.status === 200, "User A revokes device credential (200)");

      // 8. Revoked device token is immediately rejected on subsequent uploads
      const resRevokedIngest = await fetch(`${baseUrl}/api/scans/ingest`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${deviceToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(scanPayload),
      });
      assert(resRevokedIngest.status === 401, "Revoked device credential rejected on upload (401 Unauthorized)");
    }

  } finally {
    server.close();
  }

  console.log("=======================================================");
  console.log(`  SECURITY TEST SUMMARY: PASSED: ${passed} | FAILED: ${failed}`);
  console.log("=======================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runSecurityTests().catch((err) => {
  console.error("Test execution exception:", err);
  process.exit(1);
});
