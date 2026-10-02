// PhantomTrace API Test Suite
const BASE_URL = "http://localhost:5000";

async function runTests() {
  console.log("=== PHANTOMTRACE API TEST SUITE ===");
  let passed = 0;
  let failed = 0;

  async function assert(desc, condition, details = "") {
    if (condition) {
      console.log(`[PASS] ${desc}`);
      passed++;
    } else {
      console.error(`[FAIL] ${desc} - ${details}`);
      failed++;
    }
  }

  // 1. Phase 3.2 - Health Check
  try {
    const res = await fetch(`${BASE_URL}/api/health`);
    const data = await res.json();
    await assert(
      "GET /api/health returns 200 and correct status payload",
      res.status === 200 &&
        data.status === "ok" &&
        data.service === "PhantomTrace API" &&
        data.version === "1.0.0",
      JSON.stringify(data)
    );
  } catch (err) {
    await assert("GET /api/health reachable", false, err.message);
  }

  // 2. Phase 3.4 - Unauthenticated access rejection (401)
  const protectedRoutes = [
    "/api/users/me",
    "/api/endpoints",
    "/api/scans",
    "/api/processes",
    "/api/alerts",
    "/api/reports",
  ];

  for (const route of protectedRoutes) {
    try {
      const res = await fetch(`${BASE_URL}${route}`);
      await assert(
        `Unauthenticated ${route} returns 401 Unauthorized`,
        res.status === 401,
        `Status: ${res.status}`
      );
    } catch (err) {
      await assert(`Unauthenticated ${route} rejects`, false, err.message);
    }
  }

  // 3. Phase 3.4 & 3.7 - Authenticated access with Bearer token
  const tokenA = "dev-analyst-A";
  const authHeadersA = { Authorization: `Bearer ${tokenA}` };

  try {
    // Users
    const userRes = await fetch(`${BASE_URL}/api/users/me`, { headers: authHeadersA });
    const userData = await userRes.json();
    await assert(
      "GET /api/users/me returns authenticated user with derived UID",
      userRes.status === 200 && userData.user && userData.user.uid === "uid-dev-analyst-A",
      JSON.stringify(userData)
    );

    // Endpoints
    const epRes = await fetch(`${BASE_URL}/api/endpoints`, { headers: authHeadersA });
    const epData = await epRes.json();
    await assert(
      "GET /api/endpoints returns user endpoints with ownerUid matching token",
      epRes.status === 200 &&
        Array.isArray(epData.endpoints) &&
        epData.endpoints.every((ep) => ep.ownerUid === "uid-dev-analyst-A"),
      JSON.stringify(epData)
    );

    const singleEpRes = await fetch(`${BASE_URL}/api/endpoints/ep-win11-secops-01`, {
      headers: authHeadersA,
    });
    const singleEpData = await singleEpRes.json();
    await assert(
      "GET /api/endpoints/:id returns specific endpoint",
      singleEpRes.status === 200 && singleEpData.endpoint.endpointId === "ep-win11-secops-01",
      JSON.stringify(singleEpData)
    );

    // Scans
    const scansRes = await fetch(`${BASE_URL}/api/scans`, { headers: authHeadersA });
    const scansData = await scansRes.json();
    await assert(
      "GET /api/scans returns user scans with ownerUid matching token",
      scansRes.status === 200 &&
        Array.isArray(scansData.scans) &&
        scansData.scans.every((s) => s.ownerUid === "uid-dev-analyst-A"),
      JSON.stringify(scansData)
    );

    // Processes
    const procRes = await fetch(`${BASE_URL}/api/processes`, { headers: authHeadersA });
    const procData = await procRes.json();
    await assert(
      "GET /api/processes returns user processes with ownerUid matching token",
      procRes.status === 200 &&
        Array.isArray(procData.processes) &&
        procData.processes.every((p) => p.ownerUid === "uid-dev-analyst-A"),
      JSON.stringify(procData)
    );

    const singleProcRes = await fetch(`${BASE_URL}/api/processes/4812`, {
      headers: authHeadersA,
    });
    const singleProcData = await singleProcRes.json();
    await assert(
      "GET /api/processes/:id by PID returns matching process with evidence",
      singleProcRes.status === 200 &&
        singleProcData.process.pid === 4812 &&
        singleProcData.process.memoryEvidence?.present === true,
      JSON.stringify(singleProcData)
    );

    // Alerts
    const alertsRes = await fetch(`${BASE_URL}/api/alerts`, { headers: authHeadersA });
    const alertsData = await alertsRes.json();
    await assert(
      "GET /api/alerts returns user alerts with ownerUid matching token",
      alertsRes.status === 200 &&
        Array.isArray(alertsData.alerts) &&
        alertsData.alerts.every((a) => a.ownerUid === "uid-dev-analyst-A"),
      JSON.stringify(alertsData)
    );

    const singleAlertRes = await fetch(`${BASE_URL}/api/alerts/alert-pt-4812`, {
      headers: authHeadersA,
    });
    const singleAlertData = await singleAlertRes.json();
    await assert(
      "GET /api/alerts/:id returns single alert with recommendations",
      singleAlertRes.status === 200 &&
        singleAlertData.alert.id === "alert-pt-4812" &&
        Array.isArray(singleAlertData.alert.recommendedActions),
      JSON.stringify(singleAlertData)
    );

    // Reports
    const reportsRes = await fetch(`${BASE_URL}/api/reports`, { headers: authHeadersA });
    const reportsData = await reportsRes.json();
    await assert(
      "GET /api/reports returns user reports with ownerUid matching token",
      reportsRes.status === 200 &&
        Array.isArray(reportsData.reports) &&
        reportsData.reports.every((r) => r.ownerUid === "uid-dev-analyst-A"),
      JSON.stringify(reportsData)
    );

    const singleReportRes = await fetch(`${BASE_URL}/api/reports/rep-20261002-001`, {
      headers: authHeadersA,
    });
    const singleReportData = await singleReportRes.json();
    await assert(
      "GET /api/reports/:id returns single report",
      singleReportRes.status === 200 && singleReportData.report.id === "rep-20261002-001",
      JSON.stringify(singleReportData)
    );

    // 4. Phase 3.7 - User Ownership Isolation Verification
    const tokenB = "dev-analyst-B";
    const userResB = await fetch(`${BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    const userDataB = await userResB.json();
    await assert(
      "User B has isolated UID (uid-dev-analyst-B)",
      userDataB.user.uid === "uid-dev-analyst-B",
      JSON.stringify(userDataB)
    );

    const alertsResB = await fetch(`${BASE_URL}/api/alerts?ownerUid=uid-dev-analyst-A`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    const alertsDataB = await alertsResB.json();
    await assert(
      "Server ignores ?ownerUid in query and strictly returns data for User B's verified token",
      alertsDataB.alerts.every((a) => a.ownerUid === "uid-dev-analyst-B"),
      JSON.stringify(alertsDataB)
    );

  } catch (err) {
    console.error("Test execution exception:", err);
    failed++;
  }

  console.log(`\nTEST RESULTS: ${passed} PASSED, ${failed} FAILED\n`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests();
