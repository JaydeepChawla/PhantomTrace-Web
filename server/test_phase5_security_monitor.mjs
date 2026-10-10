/**
 * =====================================================================
 * PHANTOMTRACE PHASE 5: DASHBOARD SECURITY MONITOR TEST SUITE
 * =====================================================================
 * Validates Phase 5 dashboard endpoints, real-time security overview,
 * multi-vector chronological security event timeline, and system health.
 *
 * NOTE: These tests execute against an in-memory test instance.
 * They validate HTTP contracts and component integration, NOT live PostgreSQL.
 * =====================================================================
 */

import http from "http";
import { app } from "./dist/app.js";

const PORT = 5098;
const baseUrl = `http://127.0.0.1:${PORT}`;

let server;
let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    passCount++;
    console.log(`[PASS] ✓ ${message}`);
  } else {
    failCount++;
    console.error(`[FAIL] ✗ ${message}`);
  }
}

async function runTests() {
  console.log("\n=======================================================");
  console.log("  PHANTOMTRACE PHASE 5: DASHBOARD SECURITY MONITOR     ");
  console.log("=======================================================\n");

  const analystAHeaders = {
    "Content-Type": "application/json",
    Authorization: "Bearer dev-analyst-alpha",
  };

  const analystBHeaders = {
    "Content-Type": "application/json",
    Authorization: "Bearer dev-analyst-beta",
  };

  try {
    // -----------------------------------------------------------------
    // 1. Authentication & Route Protection (401 checks)
    // -----------------------------------------------------------------
    {
      const res1 = await fetch(`${baseUrl}/api/dashboard/overview`);
      assert(res1.status === 401, "Unauthenticated GET /api/dashboard/overview returns 401 Unauthorized");

      const res2 = await fetch(`${baseUrl}/api/dashboard/timeline`);
      assert(res2.status === 401, "Unauthenticated GET /api/dashboard/timeline returns 401 Unauthorized");

      const res3 = await fetch(`${baseUrl}/api/dashboard/system-health`);
      assert(res3.status === 401, "Unauthenticated GET /api/dashboard/system-health returns 401 Unauthorized");
    }

    // -----------------------------------------------------------------
    // 2. Initial Empty State Verification
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/dashboard/overview`, {
        headers: analystAHeaders,
      });
      assert(res.status === 200, "GET /api/dashboard/overview returns 200 for authenticated analyst");
      const data = await res.json();
      assert(data.overview !== undefined, "Response contains overview payload");
      assert(data.overview.totalScans === 0, "Initial totalScans is 0 (no fake demo values)");
      assert(data.overview.processFindings.totalAnalyzed === 0, "Initial processes analyzed is 0");
      assert(data.overview.lastSuccessfulScanUpload === null, "Initial lastSuccessfulScanUpload is null");
      assert(data.overview.telemetryFreshness === "NONE", "Initial telemetryFreshness is NONE");
      assert(data.overview.isRealScannerData === false, "Initial isRealScannerData is false");
    }

    // -----------------------------------------------------------------
    // 3. System Health Probe Endpoint
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/dashboard/system-health`, {
        headers: analystAHeaders,
      });
      assert(res.status === 200, "GET /api/dashboard/system-health returns 200");
      const data = await res.json();
      assert(data.health !== undefined, "Response contains health payload");
      assert(data.health.apiStatus === "ONLINE" || data.health.apiStatus === "DEGRADED", "apiStatus is defined");
      assert(data.health.apiVersion === "1.0.0", "apiVersion reports 1.0.0");
      assert(typeof data.health.apiLatencyMs === "number", "apiLatencyMs is a numeric probe measurement");
      assert(data.health.database.engine === "PostgreSQL", "database engine is PostgreSQL");
      assert(data.health.monitoringNotice.includes("periodic scan snapshots"), "monitoringNotice clarifies periodic scan snapshot model");
    }

    // -----------------------------------------------------------------
    // 4. Ingest Telemetry & Validate Overview Dynamic Aggregation
    // -----------------------------------------------------------------
    const scanId = `scan-test-${Date.now()}`;
    {
      // Ingest realistic scanner payload
      const scanPayload = {
        scan_id: scanId,
        phantomtrace_version: "PhantomTrace 1.0",
        platform: "Windows 11 Pro 64-bit",
        scan_time_seconds: 3.42,
        timestamp: new Date().toISOString(),
        summary: {
          total_processes: 215,
          highest_score: 85,
          normal: 210,
          low: 2,
          medium: 1,
          high: 1,
          critical: 1,
        },
        processes: [
          {
            pid: 1001,
            name: "explorer.exe",
            score: 0,
            level: "NORMAL",
            memory: { regions: [{ region_size: 10485760 }] },
          },
          {
            pid: 4892,
            name: "powershell.exe",
            score: 85,
            level: "CRITICAL",
            memory: { regions: [{ region_size: 5242880 }] },
          },
          {
            pid: 5120,
            name: "msedge.exe",
            score: 15,
            level: "LOW",
            memory: { regions: [{ region_size: 20971520 }] },
          },
        ],
      };

      const ingestRes = await fetch(`${baseUrl}/api/scans/ingest`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify(scanPayload),
      });
      assert(ingestRes.status === 201 || ingestRes.status === 200, "Scan ingestion returns success");

      // Verify Overview updates
      const ovRes = await fetch(`${baseUrl}/api/dashboard/overview`, {
        headers: analystAHeaders,
      });
      const ovData = await ovRes.json();
      assert(ovData.overview.totalScans >= 1, "Overview totalScans reflects ingested scan");
      assert(ovData.overview.processFindings.totalAnalyzed === 215, "processFindings totalAnalyzed matches scan");
      assert(ovData.overview.processFindings.highestThreatScore === 85, "processFindings highestThreatScore is 85");
      assert(ovData.overview.lastSuccessfulScanUpload !== null, "lastSuccessfulScanUpload contains valid timestamp");
      assert(ovData.overview.telemetryFreshness === "FRESH", "telemetryFreshness evaluates to FRESH for recent scan");
      assert(ovData.overview.isRealScannerData === true, "isRealScannerData evaluates to true");
    }

    // -----------------------------------------------------------------
    // 5. Ingest Web Threat & Domain Policy Events
    // -----------------------------------------------------------------
    {
      // Add domain policy
      const polRes = await fetch(`${baseUrl}/api/web-threats/policies`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({
          domain: "phishing-finance-portal.net",
          policyType: "BLOCK",
          reason: "Observed spoofing banking login portal",
        }),
      });
      assert(polRes.status === 201, "Created domain policy rule");

      // Add web threat event
      const wtRes = await fetch(`${baseUrl}/api/web-threats/events`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({
          domain: "phishing-finance-portal.net",
          classification: "PHISHING",
          severity: "HIGH",
          score: 88,
          browser: "msedge.exe",
          explanation: "Analyst confirmed phishing landing page.",
        }),
      });
      assert(wtRes.status === 201, "Ingested web threat event");
    }

    // -----------------------------------------------------------------
    // 6. Security Event Timeline Consolidation
    // -----------------------------------------------------------------
    {
      const tlRes = await fetch(`${baseUrl}/api/dashboard/timeline`, {
        headers: analystAHeaders,
      });
      assert(tlRes.status === 200, "GET /api/dashboard/timeline returns 200");
      const tlData = await tlRes.json();
      assert(Array.isArray(tlData.events), "timeline events returned as array");
      assert(tlData.total >= 3, `timeline total contains consolidated events (count: ${tlData.total})`);

      // Verify event types
      const types = new Set(tlData.events.map((e) => e.eventType));
      assert(types.has("SCAN_INGEST"), "Timeline contains SCAN_INGEST event");
      assert(types.has("POLICY_EVENT"), "Timeline contains POLICY_EVENT event");
      assert(types.has("WEB_THREAT"), "Timeline contains WEB_THREAT event");

      // Verify descending chronological order
      let isSorted = true;
      for (let i = 0; i < tlData.events.length - 1; i++) {
        if (new Date(tlData.events[i].timestamp) < new Date(tlData.events[i + 1].timestamp)) {
          isSorted = false;
          break;
        }
      }
      assert(isSorted, "Timeline events are sorted descending by timestamp");
    }

    // -----------------------------------------------------------------
    // 7. Timeline Filtering & Pagination
    // -----------------------------------------------------------------
    {
      // Filter by type
      const filterRes = await fetch(`${baseUrl}/api/dashboard/timeline?type=WEB_THREAT`, {
        headers: analystAHeaders,
      });
      const filterData = await filterRes.json();
      const allWeb = filterData.events.every((e) => e.eventType === "WEB_THREAT");
      assert(allWeb && filterData.events.length > 0, "Filter by type=WEB_THREAT returns only web threat events");

      // Filter by severity
      const sevRes = await fetch(`${baseUrl}/api/dashboard/timeline?severity=HIGH`, {
        headers: analystAHeaders,
      });
      const sevData = await sevRes.json();
      const allHigh = sevData.events.every((e) => e.severity === "HIGH");
      assert(allHigh, "Filter by severity=HIGH returns only HIGH severity events");

      // Pagination
      const pageRes = await fetch(`${baseUrl}/api/dashboard/timeline?limit=1&offset=0`, {
        headers: analystAHeaders,
      });
      const pageData = await pageRes.json();
      assert(pageData.events.length === 1, "Pagination limit=1 returns exactly 1 item");
      assert(pageData.limit === 1 && pageData.offset === 0, "Pagination metadata accurate");
    }

    // -----------------------------------------------------------------
    // 8. Tenant Isolation Verification
    // -----------------------------------------------------------------
    {
      const bRes = await fetch(`${baseUrl}/api/dashboard/overview`, {
        headers: analystBHeaders,
      });
      const bData = await bRes.json();
      assert(bData.overview.totalScans === 0, "Analyst B does not see Analyst A's scans (tenant isolated)");

      const bTlRes = await fetch(`${baseUrl}/api/dashboard/timeline`, {
        headers: analystBHeaders,
      });
      const bTlData = await bTlRes.json();
      assert(bTlData.total === 0, "Analyst B timeline does not leak Analyst A events");
    }

    // -----------------------------------------------------------------
    // 9. Boundary & Robustness Checks
    // -----------------------------------------------------------------
    {
      const malformedRes = await fetch(`${baseUrl}/api/dashboard/timeline?type=NONEXISTENT_TYPE&severity=XYZ&limit=-5&offset=-10`, {
        headers: analystAHeaders,
      });
      assert(malformedRes.status === 200, "Malformed timeline query parameters handled gracefully (200)");
      const malformedData = await malformedRes.json();
      assert(Array.isArray(malformedData.events), "Malformed query returns valid events array");
    }

  } catch (err) {
    console.error("Test execution exception:", err);
    failCount++;
  } finally {
    console.log("\n=======================================================");
    console.log(`  PHASE 5 TEST SUMMARY: PASSED: ${passCount} | FAILED: ${failCount}`);
    console.log("=======================================================\n");

    if (server) {
      server.close();
    }

    if (failCount > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  }
}

// Start HTTP server and execute test suite
server = http.createServer(app);
server.listen(PORT, "127.0.0.1", () => {
  runTests();
});
