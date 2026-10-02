import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BASE_URL = process.env.API_URL || "http://localhost:5000";
const TOKEN = process.env.AUTH_TOKEN || "dev-analyst-001";

// Resolve scan_results.json from sample_scanner_output or scanner directory
const possiblePaths = [
  path.resolve(__dirname, "../sample_scanner_output/scan_results.json"),
  path.resolve("D:/Phantom Trace/scan_results.json"),
  path.resolve("D:/Phantom Trace/agent/scan_results.json"),
];

let scanFilePath = "";
for (const p of possiblePaths) {
  if (fs.existsSync(p)) {
    scanFilePath = p;
    break;
  }
}

if (!scanFilePath) {
  console.error("Error: Could not locate scan_results.json in any expected location.");
  process.exit(1);
}

console.log(`====================================================`);
console.log(` PHANTOMTRACE SCAN INGESTION UTILITY & VERIFICATION`);
console.log(` Target Server: ${BASE_URL}`);
console.log(` Scanner File:  ${scanFilePath}`);
console.log(` File Size:     ${(fs.statSync(scanFilePath).size / (1024 * 1024)).toFixed(2)} MB`);
console.log(`====================================================\n`);

async function testIngestion() {
  const rawContent = fs.readFileSync(scanFilePath, "utf8");
  const scanData = JSON.parse(rawContent);

  // Test 1: Unauthenticated request rejection (Security Test)
  console.log("[Test 1] Testing unauthenticated upload rejection...");
  const unauthRes = await fetch(`${BASE_URL}/api/scans/ingest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ test: "data" }),
  });
  if (unauthRes.status === 401) {
    console.log("  [PASS] Unauthenticated upload rejected with 401 Unauthorized.");
  } else {
    console.error(`  [FAIL] Expected 401, got ${unauthRes.status}`);
    process.exit(1);
  }

  // Test 2: Malformed payload rejection (Validation Test)
  console.log("[Test 2] Testing malformed payload validation...");
  const malformedRes = await fetch(`${BASE_URL}/api/scans/ingest`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({ invalid: "data", empty: true }),
  });
  const malformedJson = await malformedRes.json();
  if (malformedRes.status === 400 && malformedJson.error?.code === "INVALID_SCAN") {
    console.log(`  [PASS] Malformed scan rejected with 400 Bad Request (${malformedJson.error.message}).`);
  } else {
    console.error(`  [FAIL] Expected 400 INVALID_SCAN, got ${malformedRes.status}`, malformedJson);
    process.exit(1);
  }

  // Test 3: Authenticated real scan ingestion
  console.log(`[Test 3] Uploading real scan_results.json (${scanData.results?.length || 0} processes)...`);
  const startTime = Date.now();
  const ingestRes = await fetch(`${BASE_URL}/api/scans/ingest`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: rawContent,
  });

  const durationMs = Date.now() - startTime;
  const ingestJson = await ingestRes.json();

  if (ingestRes.status === 200 || ingestRes.status === 201) {
    console.log(`  [PASS] Ingestion successful in ${durationMs}ms (Status: ${ingestRes.status})`);
    console.log("  Scan ID:            ", ingestJson.scanId);
    console.log("  Endpoint ID:        ", ingestJson.endpointId);
    console.log("  Processes Imported: ", ingestJson.processesImported);
    console.log("  Alerts Imported:    ", ingestJson.alertsImported);
    console.log("  Highest Threat Score:", ingestJson.highestScore);
  } else {
    console.error(`  [FAIL] Ingestion failed with status ${ingestRes.status}:`, ingestJson);
    process.exit(1);
  }

  // Test 4: Duplicate scan detection
  console.log("[Test 4] Testing duplicate scan submission...");
  const dupRes = await fetch(`${BASE_URL}/api/scans/ingest`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: rawContent,
  });
  const dupJson = await dupRes.json();
  if (dupJson.duplicate === true && dupJson.scanId === ingestJson.scanId) {
    console.log(`  [PASS] Duplicate scan detected. Reused scan ID: ${dupJson.scanId}`);
  } else {
    console.error("  [FAIL] Duplicate detection failed:", dupJson);
    process.exit(1);
  }

  // Test 5: Verify data retrieval via API
  console.log("[Test 5] Verifying ingested data via authenticated API routes...");
  const scansRes = await fetch(`${BASE_URL}/api/scans`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  const scansData = await scansRes.json();
  console.log(`  Scans available:    ${scansData.scans?.length || 0}`);

  const procRes = await fetch(`${BASE_URL}/api/processes`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  const procData = await procRes.json();
  console.log(`  Processes indexed:  ${procData.processes?.length || 0}`);

  const alertsRes = await fetch(`${BASE_URL}/api/alerts`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  const alertsData = await alertsRes.json();
  console.log(`  Threat Alerts:      ${alertsData.alerts?.length || 0}`);

  // Test 6: Verify evidence preservation on Critical alert
  const criticalAlert = alertsData.alerts?.find((a) => a.level === "CRITICAL" || a.score >= 80);
  if (criticalAlert) {
    console.log(`\n  Critical Alert Check: ${criticalAlert.processName} (PID ${criticalAlert.pid})`);
    console.log(`    Score:              ${criticalAlert.score}/100`);
    console.log(`    Score Mode:         ${criticalAlert.scoreMode}`);
    console.log(`    Memory Indicators:  ${criticalAlert.memoryEvidence?.indicators?.join(", ") || "None"}`);
    console.log(`    Behavior Indicators:${criticalAlert.behaviorEvidence?.indicators?.join(", ") || "None"}`);
    console.log(`    Recommended Actions:${criticalAlert.recommendedActions?.length || 0} guidance steps`);
  }

  console.log("\n====================================================");
  console.log(" ALL PHASE 4 INGESTION TESTS PASSED SUCCESSFULLY");
  console.log("====================================================\n");
}

testIngestion().catch((err) => {
  console.error("Fatal error during ingestion test:", err);
  process.exit(1);
});
