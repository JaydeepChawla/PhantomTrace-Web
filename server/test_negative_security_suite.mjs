/**
 * =====================================================================
 * PHANTOMTRACE STEP 13: NEGATIVE SECURITY TESTS
 * =====================================================================
 */

import { app } from "./dist/app.js";
import http from "http";
import fs from "fs";
import path from "path";

async function runNegativeSecurityTests() {
  console.log("====================================================");
  console.log(" PHANTOMTRACE NEGATIVE SECURITY TEST SUITE (STEP 13)");
  console.log("====================================================\n");

  const port = 5056;
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
    // Setup two users
    const userARes = await fetch(`${baseUrl}/api/auth/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", name: "Alice" }),
    });
    const userA = await userARes.json();

    const userBRes = await fetch(`${baseUrl}/api/auth/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "bob@example.com", name: "Bob" }),
    });
    const userB = await userBRes.json();

    // 1. Invalid pairing code -> rejected
    const badCodeRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pairingCode: "PT-INVALID-CODE",
        deviceName: "Rogue PC",
      }),
    });
    assert(
      [400, 404].includes(badCodeRes.status),
      `Test 1: Invalid pairing code rejected (HTTP ${badCodeRes.status})`
    );

    // 2. Expired pairing code -> rejected
    const { postgresService } = await import("./dist/services/postgresService.js");
    const expiredCode = "PT-EXPR-TEST";
    await postgresService.createPairingRequest({
      pairingId: "pair_expired_test",
      ownerUid: userA.user.uid,
      code: expiredCode,
      expiresAt: new Date(Date.now() - 60000).toISOString(), // 1 minute in the past
      createdAt: new Date(Date.now() - 120000).toISOString(),
      usedAt: null,
      pairedDeviceId: null,
    });
    const expiredRedeemRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pairingCode: expiredCode,
        deviceName: "Expired PC",
      }),
    });
    assert(
      expiredRedeemRes.status === 400,
      `Test 2: Expired pairing code rejected (HTTP ${expiredRedeemRes.status})`
    );

    const pairStartRes = await fetch(`${baseUrl}/api/devices/pair/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${userA.sessionToken}`,
      },
    });
    const pairStart = await pairStartRes.json();

    // Redeem it
    const redeemRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pairingCode: pairStart.pairingCode,
        deviceName: "Alice PC",
      }),
    });
    const deviceA = await redeemRes.json();
    assert([200, 201].includes(redeemRes.status), "Pairing code initially redeemed successfully");

    // 3. Reused pairing code -> rejected
    const reuseRes = await fetch(`${baseUrl}/api/devices/pair/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pairingCode: pairStart.pairingCode,
        deviceName: "Duplicate PC",
      }),
    });
    assert(
      [400, 409].includes(reuseRes.status),
      `Test 3: Reused pairing code rejected (HTTP ${reuseRes.status})`
    );

    // 4. Invalid device credential -> rejected
    const badCredRes = await fetch(`${baseUrl}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer pt_dev_fake_invalid_token_1234567890",
      },
      body: JSON.stringify({
        scanMetadata: {
          timestamp: new Date().toISOString(),
          totalProcesses: 10,
          threatCount: 0,
        },
        processes: [],
      }),
    });
    assert(
      badCredRes.status === 401,
      "Test 4: Invalid device credential rejected (HTTP 401)"
    );

    // Upload a valid scan with deviceA.deviceToken
    const validUploadRes = await fetch(`${baseUrl}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${deviceA.deviceToken}`,
      },
      body: JSON.stringify({
        scanMetadata: {
          timestamp: new Date().toISOString(),
          totalProcesses: 15,
          threatCount: 0,
          highestScore: 5,
        },
        processes: [
          {
            pid: 1234,
            name: "testproc.exe",
            threatScore: 5,
            threatLevel: "clean",
          },
        ],
      }),
    });
    assert(validUploadRes.status === 201, "Valid scan uploaded by deviceA");

    // 5. Revoked device -> rejected
    const revokeRes = await fetch(
      `${baseUrl}/api/devices/${deviceA.deviceId}/revoke`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${userA.sessionToken}`,
        },
      }
    );
    assert(revokeRes.status === 200, "Device successfully revoked by owner");

    const uploadAfterRevokeRes = await fetch(`${baseUrl}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${deviceA.deviceToken}`,
      },
      body: JSON.stringify({
        scanMetadata: {
          timestamp: new Date().toISOString(),
          totalProcesses: 15,
        },
      }),
    });
    assert(
      uploadAfterRevokeRes.status === 401,
      "Test 5: Revoked device upload rejected (HTTP 401)"
    );

    // 6. User A attempts to access User B's scan -> rejected
    // Upload a scan for User B first
    const pairBStart = await (
      await fetch(`${baseUrl}/api/devices/pair/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${userB.sessionToken}`,
        },
      })
    ).json();
    const deviceB = await (
      await fetch(`${baseUrl}/api/devices/pair/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairingCode: pairBStart.pairingCode,
          deviceName: "Bob PC",
        }),
      })
    ).json();

    const bobUpload = await fetch(`${baseUrl}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${deviceB.deviceToken}`,
      },
      body: JSON.stringify({
        scanMetadata: {
          timestamp: new Date().toISOString(),
          totalProcesses: 42,
          threatCount: 1,
        },
        processes: [
          {
            pid: 9999,
            name: "bob_secret.exe",
            threatScore: 85,
            threatLevel: "critical",
          },
        ],
      }),
    });
    assert(bobUpload.status === 201, "Bob uploaded private scan");

    // Alice queries /api/scans
    const aliceScansRes = await fetch(`${baseUrl}/api/scans`, {
      headers: { Authorization: `Bearer ${userA.sessionToken}` },
    });
    const aliceScans = await aliceScansRes.json();
    const aliceCanSeeBob = Array.isArray(aliceScans.data)
      ? aliceScans.data.some((s) => s.ownerUid === userB.user.uid)
      : false;
    assert(
      !aliceCanSeeBob,
      "Test 6: User A cannot see User B's scan (Strict Partitioning)"
    );

    // 7. Owner API key absent from Agent -> PASS
    const agentDir = fs.existsSync(path.resolve("phantomtrace-agent"))
      ? path.resolve("phantomtrace-agent")
      : path.resolve("..", "phantomtrace-agent");
    function walkDir(dir, fileList = []) {
      if (!fs.existsSync(dir)) return fileList;
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        if (fs.statSync(fullPath).isDirectory()) {
          if (!file.includes("venv") && !file.includes("__pycache__")) {
            walkDir(fullPath, fileList);
          }
        } else if (file.endsWith(".py") || file.endsWith(".json")) {
          fileList.push(fullPath);
        }
      }
      return fileList;
    }
    const agentFiles = walkDir(agentDir);
    let ownerKeyFound = false;
    for (const f of agentFiles) {
      if (f.endsWith("cloud_auth.json")) continue;
      const content = fs.readFileSync(f, "utf8");
      if (
        content.includes("pt_live_") ||
        (content.includes("PHANTOMTRACE_API_KEY") && !content.includes("header"))
      ) {
        ownerKeyFound = true;
        console.error(`Found potential owner key in ${f}`);
      }
    }
    assert(!ownerKeyFound, "Test 7: Owner API key absent from Agent codebase");

    // 8. Database password absent from Agent -> PASS
    let dbSecretFound = false;
    for (const f of agentFiles) {
      const content = fs.readFileSync(f, "utf8");
      if (
        content.includes("DATABASE_URL") ||
        content.includes("postgres://") ||
        content.includes("postgresql://")
      ) {
        dbSecretFound = true;
      }
    }
    assert(!dbSecretFound, "Test 8: Database credentials absent from Agent");

    // 9. Arbitrary command endpoint absent -> PASS
    const localApiPy = fs.readFileSync(
      path.join(agentDir, "agent_service", "local_api.py"),
      "utf8"
    );
    const hasExecEndpoint =
      localApiPy.includes("exec(") ||
      localApiPy.includes("eval(") ||
      localApiPy.includes("os.system") ||
      localApiPy.includes("/api/command") ||
      localApiPy.includes("/api/run");
    assert(
      !hasExecEndpoint,
      "Test 9: Arbitrary command execution endpoint absent from Agent"
    );

    // 10. Local Agent remains bound only to 127.0.0.1
    const mainPy = fs.readFileSync(
      path.join(agentDir, "agent_service", "main.py"),
      "utf8"
    );
    const bindsOnlyLoopback =
      mainPy.includes("127.0.0.1") &&
      !mainPy.includes("0.0.0.0") &&
      !localApiPy.includes("0.0.0.0");
    assert(
      bindsOnlyLoopback,
      "Test 10: Local Agent remains strictly bound to 127.0.0.1 (Loopback)"
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

runNegativeSecurityTests().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
