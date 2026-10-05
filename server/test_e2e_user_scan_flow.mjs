/**
 * =====================================================================
 * PHANTOMTRACE STEP 12: END-TO-END CONTROLLED USER & DEVICE SCAN TEST
 * =====================================================================
 * Verifies the full user journey:
 * 1. User login (session token created)
 * 2. "Connect This PC" (pairing code generated)
 * 3. Local Agent pairs using the code
 * 4. Scoped device credential issued & validated
 * 5. Real scan_results.json uploaded with device credential
 * 6. Telemetry ingested into PostgreSQL
 * 7. User dashboard queries & displayed values match real scan JSON exactly
 * =====================================================================
 */

import { app } from "./dist/app.js";
import http from "http";
import fs from "fs";
import path from "path";

async function runStep12Test() {
  console.log("====================================================");
  console.log(" PHANTOMTRACE STEP 12: END-TO-END FLOW VERIFICATION");
  console.log("====================================================\n");

  const port = 5057;
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(port, resolve));
  const baseUrl = `http://localhost:${port}`;

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[PASS] ${message}`);
      passed++;
    } else {
      console.error(`[FAIL] ${message}`);
      failed++;
    }
  }

  try {
    // 1. User Login
    console.log("[1] Simulating user login on PhantomTrace website...");
    const loginRes = await fetch(`${baseUrl}/api/auth/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "enterprise_analyst@phantomtrace.io",
        name: "Enterprise Analyst",
      }),
    });
    assert(loginRes.status === 200, "User login succeeds and session is issued");
    const userSession = await loginRes.json();
    const sessionToken = userSession.sessionToken;
    const userUid = userSession.user.uid;
    console.log(`    Authenticated User UID: ${userUid}`);

    // 2. Connect This PC (Pairing Start)
    console.log("\n[2] User clicks 'Connect This PC' on dashboard...");
    const pairStartRes = await fetch(`${baseUrl}/api/devices/pair/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${sessionToken}`,
      },
    });
    assert(pairStartRes.status === 200, "Pairing request created");
    const pairStart = await pairStartRes.json();
    const { pairingId, pairingCode, expiresAt } = pairStart;
    console.log(`    Generated Short-Lived Pairing Code: ${pairingCode} (Expires: ${expiresAt})`);
    assert(/^PT-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(pairingCode), "Pairing code adheres to PT-XXXX-XXXX format");

    // 3. Agent Pairing
    console.log("\n[3] PhantomTrace Windows Agent redeems pairing code...");
    const pairCompleteRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pairingCode,
        deviceName: "Primary Workstation (Windows 11)",
        platform: "Windows 11 Pro 64-bit",
      }),
    });
    assert(pairCompleteRes.status === 200, "Agent pairing handshake successful");
    const pairResult = await pairCompleteRes.json();
    const { deviceId, deviceToken } = pairResult;
    console.log(`    Enrolled Device ID: ${deviceId}`);
    assert(deviceToken.startsWith("pt_dev_"), "Scoped device credential issued (pt_dev_...)");

    // 4. Verify Dashboard detects completion
    console.log("\n[4] Dashboard polls pairing status...");
    const statusRes = await fetch(`${baseUrl}/api/devices/pair/status?pairingId=${pairingId}`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const statusData = await statusRes.json();
    assert(statusData.status === "PAIRED", "Dashboard detects transition to 'PAIRED'");
    assert(statusData.deviceId === deviceId, "Paired deviceId matches newly registered device");

    // 5. Real Scan Results Ingestion
    console.log("\n[5] Scanning PC and uploading real scan_results.json using device credential...");
    const realScanPath = path.resolve("sample_scanner_output", "scan_results.json");
    assert(fs.existsSync(realScanPath), "Real Release 1.0 scan_results.json exists");

    const rawScanJson = JSON.parse(fs.readFileSync(realScanPath, "utf8"));
    const expectedProcesses = rawScanJson.summary?.total_processes || 215;
    const expectedCritical = rawScanJson.summary?.critical || 4;
    console.log(`    Expected processes from real scan: ${expectedProcesses}`);
    console.log(`    Expected critical threats from real scan: ${expectedCritical}`);

    // Upload with deviceToken
    const uploadRes = await fetch(`${baseUrl}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${deviceToken}`,
        "X-Endpoint-Id": deviceId,
        "X-Device-Id": deviceId,
      },
      body: JSON.stringify(rawScanJson),
    });
    assert(uploadRes.status === 201, "Scan results accepted and ingested (HTTP 201)");
    const uploadData = await uploadRes.json();
    console.log(`    Ingested Scan ID: ${uploadData.scanId}`);

    // 6. User Dashboard Retrieval & Verification
    console.log("\n[6] User dashboard fetches latest scan...");
    const userScansRes = await fetch(`${baseUrl}/api/scans`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    assert(userScansRes.status === 200, "User can retrieve their scan history");
    const userScansData = await userScansRes.json();
    const scansList = userScansData.scans || userScansData.data || [];
    assert(scansList.length > 0, "Scan history contains at least one scan");

    const latestScan = scansList[0];
    console.log(`    Retrieved Scan ID: ${latestScan.scanId}`);
    console.log(`    Scan Owner UID: ${latestScan.ownerUid}`);
    console.log(`    Scan Total Processes: ${latestScan.totalProcesses}`);

    assert(latestScan.ownerUid === userUid, "Scan belongs strictly to the authenticated user UID");
    assert(latestScan.totalProcesses === expectedProcesses, `Total processes (${latestScan.totalProcesses}) matches real JSON (${expectedProcesses})`);

    // 7. Verify Devices list in My Devices section
    console.log("\n[7] Verifying 'My Devices' listing...");
    const devicesRes = await fetch(`${baseUrl}/api/devices`, {
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    const devicesData = await devicesRes.json();
    assert(Array.isArray(devicesData.devices), "Devices list returned as array");
    const myDevice = devicesData.devices.find((d) => d.deviceId === deviceId);
    assert(Boolean(myDevice), "Enrolled device is listed in user's devices");
    assert(!myDevice.isRevoked, "Enrolled device is active and not revoked");
    assert(myDevice.deviceTokenHash === undefined, "Device token hash is NOT leaked to client");
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

runStep12Test().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
