/**
 * =====================================================================
 * PHANTOMTRACE DEVICE PAIRING & USER ISOLATION TEST SUITE
 * =====================================================================
 * Tests the complete end-to-end device enrollment, token issuance,
 * authenticated upload via device token, user isolation, and revocation.
 * =====================================================================
 */

import { app } from "./dist/app.js";
import http from "http";

async function runTests() {
  console.log("====================================================");
  console.log(" PHANTOMTRACE DEVICE PAIRING & AUTH TEST SUITE");
  console.log("====================================================\n");

  const port = 5055;
  const server = http.createServer(app);

  await new Promise((resolve) => server.listen(port, resolve));
  const baseUrl = `http://localhost:${port}`;
  console.log(`[+] Test server running on ${baseUrl}`);

  let passed = 0;
  let failed = 0;

  function assert(title, condition, details = "") {
    if (condition) {
      console.log(`[PASS] ${title}`);
      passed++;
    } else {
      console.error(`[FAIL] ${title} - ${details}`);
      failed++;
    }
  }

  try {
    // -----------------------------------------------------------------
    // 1. Establish Public User A Session
    // -----------------------------------------------------------------
    const userARes = await fetch(`${baseUrl}/api/auth/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "analyst_a@phantomtrace.local", displayName: "Analyst Alice" }),
    });
    const userAData = await userARes.json();
    assert(
      "Public User A registers and obtains session token",
      userARes.status === 200 && userAData.sessionToken && userAData.sessionToken.startsWith("pt_usr_"),
      JSON.stringify(userAData)
    );

    const userAToken = userAData.sessionToken;
    const userAUid = userAData.user.uid;

    // -----------------------------------------------------------------
    // 2. User A Initiates Device Pairing ("Connect This PC")
    // -----------------------------------------------------------------
    const pairStartRes = await fetch(`${baseUrl}/api/devices/pair/start`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${userAToken}`,
      },
    });
    const pairStartData = await pairStartRes.json();
    assert(
      "User A creates short-lived pairing request",
      pairStartRes.status === 200 &&
        typeof pairStartData.pairingCode === "string" &&
        pairStartData.pairingCode.startsWith("PT-"),
      JSON.stringify(pairStartData)
    );

    const pairingCode = pairStartData.pairingCode;
    const pairingId = pairStartData.pairingId;

    // Verify initial status is PENDING
    const initialStatusRes = await fetch(`${baseUrl}/api/devices/pair/status?pairingId=${pairingId}`, {
      headers: { Authorization: `Bearer ${userAToken}` },
    });
    const initialStatusData = await initialStatusRes.json();
    assert(
      "Pairing status before agent redemption is PENDING",
      initialStatusRes.status === 200 && initialStatusData.status === "PENDING",
      JSON.stringify(initialStatusData)
    );

    // -----------------------------------------------------------------
    // 3. Agent Completes Pairing
    // -----------------------------------------------------------------
    const pairCompleteRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pairingCode: pairingCode,
        deviceName: "Alice-Win11-Workstation",
        platform: "Windows 11 Enterprise x86_64",
      }),
    });
    const pairCompleteData = await pairCompleteRes.json();
    assert(
      "Agent redeems pairing code and receives scoped device credential",
      pairCompleteRes.status === 200 &&
        pairCompleteData.deviceToken &&
        pairCompleteData.deviceToken.startsWith("pt_dev_") &&
        pairCompleteData.deviceId &&
        pairCompleteData.ownerUid === userAUid,
      JSON.stringify(pairCompleteData)
    );

    const deviceToken = pairCompleteData.deviceToken;
    const deviceId = pairCompleteData.deviceId;

    // -----------------------------------------------------------------
    // 4. Verify Single-Use & Expiration Rejection
    // -----------------------------------------------------------------
    const reuseRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairingCode: pairingCode }),
    });
    assert(
      "Reusing the same pairing code is rejected (Single-use enforcement)",
      reuseRes.status === 409 || reuseRes.status === 400,
      `Status: ${reuseRes.status}`
    );

    const invalidCodeRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairingCode: "PT-INVALID-CODE" }),
    });
    assert(
      "Invalid pairing code is rejected",
      invalidCodeRes.status === 404 || invalidCodeRes.status === 400,
      `Status: ${invalidCodeRes.status}`
    );

    // -----------------------------------------------------------------
    // 5. Dashboard Polls Status and Detects PAIRED
    // -----------------------------------------------------------------
    const pairedStatusRes = await fetch(`${baseUrl}/api/devices/pair/status?pairingId=${pairingId}`, {
      headers: { Authorization: `Bearer ${userAToken}` },
    });
    const pairedStatusData = await pairedStatusRes.json();
    assert(
      "Dashboard detects pairing transition to PAIRED with matching deviceId",
      pairedStatusRes.status === 200 &&
        pairedStatusData.status === "PAIRED" &&
        pairedStatusData.deviceId === deviceId,
      JSON.stringify(pairedStatusData)
    );

    // -----------------------------------------------------------------
    // 6. Enumerate User Devices
    // -----------------------------------------------------------------
    const devicesListRes = await fetch(`${baseUrl}/api/devices`, {
      headers: { Authorization: `Bearer ${userAToken}` },
    });
    const devicesListData = await devicesListRes.json();
    assert(
      "GET /api/devices lists User A's newly registered device without leaking token hash",
      devicesListRes.status === 200 &&
        Array.isArray(devicesListData.devices) &&
        devicesListData.devices.some((d) => d.deviceId === deviceId && !d.deviceTokenHash),
      JSON.stringify(devicesListData)
    );

    // -----------------------------------------------------------------
    // 7. Authenticated Scan Upload Using Device Token
    // -----------------------------------------------------------------
    const sampleScan = {
      timestamp: "2026-10-05 17:18:36 UTC",
      endpoint_id: deviceId,
      scanner_version: "PhantomTrace Windows Release 1.0",
      total_processes: 246,
      highest_score: 94,
      processes: [
        {
          pid: 4820,
          name: "powershell.exe",
          path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          threat_score: 94,
          threat_level: "CRITICAL",
          score_mode: "CORRELATED",
          command_line: "powershell.exe -enc JABzACAAPQAgAE4AZQB3...",
          memory_evidence: { indicators: ["PAGE_EXECUTE_READWRITE unbacked region"] },
          behavior_evidence: { indicators: ["Encoded command line execution"] },
        },
      ],
      threat_alerts: [
        {
          id: "alert-dev-test-1",
          pid: 4820,
          process_name: "powershell.exe",
          score: 94,
          level: "CRITICAL",
          title: "Reflective Shellcode Injection",
        },
      ],
    };

    const uploadRes = await fetch(`${baseUrl}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${deviceToken}`,
        "X-Endpoint-Id": deviceId,
      },
      body: JSON.stringify(sampleScan),
    });
    const uploadData = await uploadRes.json();
    assert(
      "Scan upload accepted using scoped device credential",
      uploadRes.status === 201 || uploadRes.status === 200,
      JSON.stringify(uploadData)
    );

    // -----------------------------------------------------------------
    // 8. User A Sees the Scan in Dashboard
    // -----------------------------------------------------------------
    const userAScansRes = await fetch(`${baseUrl}/api/scans`, {
      headers: { Authorization: `Bearer ${userAToken}` },
    });
    const userAScansData = await userAScansRes.json();
    assert(
      "User A retrieves their uploaded scan in /api/scans",
      userAScansRes.status === 200 &&
        Array.isArray(userAScansData.scans) &&
        userAScansData.scans.length > 0 &&
        userAScansData.scans[0].endpointId === deviceId,
      JSON.stringify(userAScansData)
    );

    // -----------------------------------------------------------------
    // 9. Multi-Tenant User Isolation: User B Cannot See User A's Data
    // -----------------------------------------------------------------
    const userBRes = await fetch(`${baseUrl}/api/auth/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "analyst_b@phantomtrace.local", displayName: "Analyst Bob" }),
    });
    const userBData = await userBRes.json();
    const userBToken = userBData.sessionToken;

    const userBScansRes = await fetch(`${baseUrl}/api/scans`, {
      headers: { Authorization: `Bearer ${userBToken}` },
    });
    const userBScansData = await userBScansRes.json();
    assert(
      "User Isolation: User B cannot see User A's scans (zero scans returned)",
      userBScansRes.status === 200 &&
        Array.isArray(userBScansData.scans) &&
        userBScansData.scans.length === 0,
      JSON.stringify(userBScansData)
    );

    const userBDevicesRes = await fetch(`${baseUrl}/api/devices`, {
      headers: { Authorization: `Bearer ${userBToken}` },
    });
    const userBDevicesData = await userBDevicesRes.json();
    assert(
      "User Isolation: User B cannot see User A's devices",
      userBDevicesRes.status === 200 &&
        Array.isArray(userBDevicesData.devices) &&
        userBDevicesData.devices.length === 0,
      JSON.stringify(userBDevicesData)
    );

    // -----------------------------------------------------------------
    // 10. Device Revocation & Immediate Upload Lockout
    // -----------------------------------------------------------------
    const revokeRes = await fetch(`${baseUrl}/api/devices/${deviceId}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${userAToken}` },
    });
    assert(
      "User A successfully revokes device",
      revokeRes.status === 200,
      `Status: ${revokeRes.status}`
    );

    // Attempting upload with revoked device token MUST be rejected
    const blockedUploadRes = await fetch(`${baseUrl}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${deviceToken}`,
      },
      body: JSON.stringify(sampleScan),
    });
    assert(
      "Upload using revoked device token is rejected (401 Unauthorized)",
      blockedUploadRes.status === 401,
      `Status: ${blockedUploadRes.status}`
    );

  } finally {
    server.close();
  }

  console.log("\n====================================================");
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log("====================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
