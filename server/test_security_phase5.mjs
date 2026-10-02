import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BASE_URL = process.env.API_URL || "http://localhost:5000";
const SCAN_FILE = path.resolve(__dirname, "../sample_scanner_output/scan_results.json");

async function runSecurityValidation() {
  console.log("====================================================");
  console.log(" PHANTOMTRACE PHASE 5: SECURITY & VALIDATION SUITE");
  console.log(` Target Server: ${BASE_URL}`);
  console.log("====================================================\n");

  const results = [];
  function record(testName, passed, expected, actual, category = "General") {
    results.push({ testName, passed, expected, actual, category });
    const mark = passed ? "[PASS]" : "[FAIL]";
    console.log(`${mark} [${category}] ${testName}`);
    if (!passed) {
      console.error(`       Expected: ${expected}`);
      console.error(`       Actual:   ${actual}`);
    }
  }

  // -----------------------------------------------------------------
  // 1. PHASE 5.1 & 5.11: API SECURITY HEADERS AUDIT
  // -----------------------------------------------------------------
  try {
    const healthRes = await fetch(`${BASE_URL}/api/health`);
    record(
      "X-Powered-By header is removed",
      healthRes.headers.get("x-powered-by") === null,
      "null",
      healthRes.headers.get("x-powered-by") || "null",
      "Headers"
    );
    record(
      "X-Content-Type-Options is nosniff",
      healthRes.headers.get("x-content-type-options") === "nosniff",
      "nosniff",
      healthRes.headers.get("x-content-type-options"),
      "Headers"
    );
    record(
      "X-Frame-Options is DENY",
      healthRes.headers.get("x-frame-options") === "DENY",
      "DENY",
      healthRes.headers.get("x-frame-options"),
      "Headers"
    );
  } catch (err) {
    record("Security headers reachable", false, "200 OK", err.message, "Headers");
  }

  // -----------------------------------------------------------------
  // 2. PHASE 5.12: CORS VALIDATION
  // -----------------------------------------------------------------
  try {
    // Authorized origin
    const authCors = await fetch(`${BASE_URL}/api/health`, {
      headers: { Origin: "http://localhost:5173" },
    });
    record(
      "CORS allows trusted dev origin http://localhost:5173",
      authCors.headers.get("access-control-allow-origin") === "http://localhost:5173",
      "http://localhost:5173",
      authCors.headers.get("access-control-allow-origin"),
      "CORS"
    );

    // Unauthorized origin
    const badCors = await fetch(`${BASE_URL}/api/health`, {
      headers: { Origin: "http://malicious-attacker-domain.com" },
    });
    record(
      "CORS blocks unauthorized origin http://malicious-attacker-domain.com",
      badCors.status === 403 || badCors.headers.get("access-control-allow-origin") !== "http://malicious-attacker-domain.com",
      "Blocked or 403",
      `Status: ${badCors.status}, Origin Header: ${badCors.headers.get("access-control-allow-origin")}`,
      "CORS"
    );
  } catch (err) {
    record("CORS tests executed", false, "Passed", err.message, "CORS");
  }

  // -----------------------------------------------------------------
  // 3. PHASE 5.3: AUTHENTICATION TESTING
  // -----------------------------------------------------------------
  const protectedRoutes = [
    { method: "GET", path: "/api/users/me" },
    { method: "GET", path: "/api/endpoints" },
    { method: "GET", path: "/api/endpoints/ep-123" },
    { method: "GET", path: "/api/scans" },
    { method: "GET", path: "/api/scans/scan-123" },
    { method: "GET", path: "/api/processes" },
    { method: "GET", path: "/api/processes/123" },
    { method: "GET", path: "/api/alerts" },
    { method: "GET", path: "/api/alerts/alt-123" },
    { method: "GET", path: "/api/reports" },
    { method: "GET", path: "/api/reports/rep-123" },
    { method: "POST", path: "/api/scans/ingest" },
  ];

  for (const r of protectedRoutes) {
    // Unauthenticated
    const resNoAuth = await fetch(`${BASE_URL}${r.path}`, { method: r.method });
    record(
      `Unauthenticated ${r.method} ${r.path} returns 401`,
      resNoAuth.status === 401,
      "401",
      String(resNoAuth.status),
      "Authentication"
    );

    // Malformed Auth Header
    const resBadAuth = await fetch(`${BASE_URL}${r.path}`, {
      method: r.method,
      headers: { Authorization: "InvalidTokenFormat" },
    });
    record(
      `Malformed Auth ${r.method} ${r.path} returns 401`,
      resBadAuth.status === 401,
      "401",
      String(resBadAuth.status),
      "Authentication"
    );
  }

  // -----------------------------------------------------------------
  // 4. PHASE 5.6: INPUT VALIDATION
  // -----------------------------------------------------------------
  const testIds = [
    { desc: "Path traversal", id: "../../../etc/passwd" },
    { desc: "Special characters", id: "<script>alert(1)</script>" },
    { desc: "Overlong ID (>128 chars)", id: "A".repeat(150) },
    { desc: "Whitespace ID", id: "   " },
  ];

  const paramEndpoints = [
    "/api/endpoints",
    "/api/scans",
    "/api/processes",
    "/api/alerts",
    "/api/reports",
  ];

  for (const endpoint of paramEndpoints) {
    for (const testId of testIds) {
      const url = `${BASE_URL}${endpoint}/${encodeURIComponent(testId.id)}`;
      const res = await fetch(url, {
        headers: { Authorization: "Bearer dev-analyst-001" },
      });
      const data = await res.json().catch(() => ({}));
      record(
        `Input validation on ${endpoint} with ${testId.desc} returns 400`,
        res.status === 400 && data.error?.code === "INVALID_PARAMETER",
        "400 INVALID_PARAMETER",
        `${res.status} ${data.error?.code || ""}`,
        "Input Validation"
      );
    }
  }

  // -----------------------------------------------------------------
  // 5. PHASE 5.7: SCAN INGESTION VALIDATION
  // -----------------------------------------------------------------
  const ingestCases = [
    { desc: "Empty object payload", body: {}, expectedCode: "INVALID_SCAN" },
    { desc: "Missing results collection", body: { summary: { total_processes: 10, highest_score: 50 } }, expectedCode: "INVALID_SCAN" },
    { desc: "Missing summary object", body: { results: [] }, expectedCode: "INVALID_SCAN" },
    { desc: "Non-numeric summary scores", body: { results: [], summary: { total_processes: "ten", highest_score: "high" } }, expectedCode: "INVALID_SCAN" },
  ];

  for (const tc of ingestCases) {
    const res = await fetch(`${BASE_URL}/api/scans/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer dev-analyst-001",
      },
      body: JSON.stringify(tc.body),
    });
    const json = await res.json().catch(() => ({}));
    record(
      `Scan Ingestion rejects ${tc.desc} with 400`,
      res.status === 400 && json.error?.code === tc.expectedCode,
      `400 ${tc.expectedCode}`,
      `${res.status} ${json.error?.code || ""}`,
      "Ingestion Validation"
    );
  }

  // -----------------------------------------------------------------
  // 6. PHASE 5.8, 5.9, 5.24, 5.25: REAL DATA INGESTION & PERFORMANCE
  // -----------------------------------------------------------------
  const rawScannerText = fs.readFileSync(SCAN_FILE, "utf8");
  const rawScannerJson = JSON.parse(rawScannerText);

  console.log("\n[Performance & Large Scan Test] Ingesting real 21.6MB scan payload...");
  const t0 = performance.now();
  const validIngestRes = await fetch(`${BASE_URL}/api/scans/ingest`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer dev-analyst-UserA",
    },
    body: rawScannerText,
  });
  const ingestDuration = Math.round(performance.now() - t0);
  const ingestData = await validIngestRes.json();

  record(
    "Real scan ingestion succeeds with 200/201",
    validIngestRes.status === 200 || validIngestRes.status === 201,
    "200 or 201",
    String(validIngestRes.status),
    "Data Ingestion"
  );
  record(
    `Ingestion performance is fast (< 1500ms, actual: ${ingestDuration}ms)`,
    ingestDuration < 1500,
    "< 1500ms",
    `${ingestDuration}ms`,
    "Performance"
  );
  record(
    "Processes count matches real scanner output (215 processes)",
    ingestData.processesImported === 215,
    "215",
    String(ingestData.processesImported),
    "Data Integrity"
  );
  record(
    "Threat alerts count matches real scanner output (32 alerts)",
    ingestData.alertsImported === 32,
    "32",
    String(ingestData.alertsImported),
    "Data Integrity"
  );
  record(
    "Highest threat score matches scanner score (85/100, no recalculation)",
    ingestData.highestScore === 85,
    "85",
    String(ingestData.highestScore),
    "Score Integrity"
  );

  // -----------------------------------------------------------------
  // 7. PHASE 5.23: DUPLICATE INGESTION TEST
  // -----------------------------------------------------------------
  const dupRes = await fetch(`${BASE_URL}/api/scans/ingest`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer dev-analyst-UserA",
    },
    body: rawScannerText,
  });
  const dupData = await dupRes.json();
  record(
    "Duplicate scan submission detects existing scan and prevents duplication",
    dupData.duplicate === true && dupData.scanId === ingestData.scanId,
    `duplicate: true, scanId: ${ingestData.scanId}`,
    `duplicate: ${dupData.duplicate}, scanId: ${dupData.scanId}`,
    "Duplicate Handling"
  );

  // -----------------------------------------------------------------
  // 8. PHASE 5.4: AUTHORIZATION & TENANT ISOLATION
  // -----------------------------------------------------------------
  // User B query scans
  const userBScansRes = await fetch(`${BASE_URL}/api/scans`, {
    headers: { Authorization: "Bearer dev-analyst-UserB" },
  });
  const userBScansData = await userBScansRes.json();
  const userBSeesUserAScan = userBScansData.scans?.some((s) => s.scanId === ingestData.scanId);
  record(
    "User B cannot see User A's uploaded scan in scan list",
    !userBSeesUserAScan,
    "false (isolated)",
    String(userBSeesUserAScan),
    "Authorization"
  );

  // User B direct attempt to access User A's scan by ID
  const userBDirectScanRes = await fetch(`${BASE_URL}/api/scans/${ingestData.scanId}`, {
    headers: { Authorization: "Bearer dev-analyst-UserB" },
  });
  record(
    "User B direct request for User A's scan ID is blocked (404 Not Found)",
    userBDirectScanRes.status === 404,
    "404",
    String(userBDirectScanRes.status),
    "Authorization"
  );

  // User B attempting to bypass via ?ownerUid=UserA
  const userBParamTamper = await fetch(`${BASE_URL}/api/scans?ownerUid=uid-dev-analyst-UserA`, {
    headers: { Authorization: "Bearer dev-analyst-UserB" },
  });
  const userBParamData = await userBParamTamper.json();
  const tamperSuccess = userBParamData.scans?.some((s) => s.ownerUid === "uid-dev-analyst-UserA");
  record(
    "Tampering with ?ownerUid=UserA is strictly ignored (no data leak)",
    !tamperSuccess,
    "false (tamper ignored)",
    String(tamperSuccess),
    "Authorization"
  );

  // -----------------------------------------------------------------
  // 9. PHASE 5.8: FORENSIC EVIDENCE PRESERVATION CHECK
  // -----------------------------------------------------------------
  const proc7476Res = await fetch(`${BASE_URL}/api/processes/7476`, {
    headers: { Authorization: "Bearer dev-analyst-UserA" },
  });
  const proc7476Data = await proc7476Res.json();
  const p7476 = proc7476Data.process;

  record(
    "Process 7476 PID preserved",
    p7476?.pid === 7476,
    "7476",
    String(p7476?.pid),
    "Evidence Integrity"
  );
  record(
    "Process 7476 Name preserved (powershell.exe)",
    p7476?.name === "powershell.exe",
    "powershell.exe",
    String(p7476?.name),
    "Evidence Integrity"
  );
  record(
    "Process 7476 Executable Path preserved",
    p7476?.executablePath?.includes("System32"),
    "Contains System32",
    p7476?.executablePath || "missing",
    "Evidence Integrity"
  );
  record(
    "Process 7476 Threat Score preserved (85/100)",
    p7476?.threatScore === 85,
    "85",
    String(p7476?.threatScore),
    "Evidence Integrity"
  );
  record(
    "Process 7476 Score Mode preserved (CORRELATED)",
    p7476?.scoreMode === "CORRELATED",
    "CORRELATED",
    p7476?.scoreMode || "missing",
    "Evidence Integrity"
  );
  record(
    "Process 7476 RWX Memory Region count preserved (26 regions)",
    p7476?.memoryEvidence?.rwxRegions === 26,
    "26",
    String(p7476?.memoryEvidence?.rwxRegions),
    "Evidence Integrity"
  );
  record(
    "Process 7476 Memory Indicators preserved (EXECUTABLE_WRITABLE_MEMORY, etc.)",
    p7476?.memoryEvidence?.indicators?.includes("EXECUTABLE_WRITABLE_MEMORY"),
    "true",
    String(p7476?.memoryEvidence?.indicators?.includes("EXECUTABLE_WRITABLE_MEMORY")),
    "Evidence Integrity"
  );
  record(
    "Process 7476 Behavioral Indicators preserved (SCRIPT_INTERPRETER_ACTIVITY)",
    p7476?.behaviorEvidence?.indicators?.includes("SCRIPT_INTERPRETER_ACTIVITY"),
    "true",
    String(p7476?.behaviorEvidence?.indicators?.includes("SCRIPT_INTERPRETER_ACTIVITY")),
    "Evidence Integrity"
  );
  record(
    "Process 7476 Investigation Guidance generated without destructive controls",
    Array.isArray(p7476?.responseRecommendation?.investigationSteps) &&
      p7476.responseRecommendation.readOnlyNotice?.includes("read-only"),
    "Read-only guidance preserved",
    "Preserved",
    "Read-Only Validation"
  );

  // Summary
  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.filter((r) => !r.passed).length;

  console.log("\n====================================================");
  console.log(` PHASE 5 VALIDATION COMPLETE: ${passedCount} PASSED, ${failedCount} FAILED`);
  console.log("====================================================\n");

  return { passedCount, failedCount, results };
}

runSecurityValidation().then(({ failedCount }) => {
  process.exit(failedCount > 0 ? 1 : 0);
}).catch((err) => {
  console.error("Fatal test suite error:", err);
  process.exit(1);
});
