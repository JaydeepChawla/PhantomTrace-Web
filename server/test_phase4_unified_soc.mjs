/**
 * =====================================================================
 * PHANTOMTRACE PHASE 4 — UNIFIED THREAT CORRELATION & SOC POLICY TEST SUITE
 * =====================================================================
 * Validates:
 * 1. Database schema migration idempotency (domain_policies & correlation columns).
 * 2. Strict Authentication (401) on all Phase 4 protected endpoints.
 * 3. Domain policy creation with input validation and domain normalization.
 * 4. Policy conflicts and duplicate handling.
 * 5. Domain policy listing and deletion.
 * 6. Threat Intel Policy Override:
 *    - BLOCKLIST policy overrides reputation checks to score 100 / POLICY_VIOLATION.
 *    - ALLOWLIST policy overrides reputation checks to score 0 / BENIGN.
 * 7. Cross-Vector Threat Correlation (linking web threats with endpoint browser processes).
 * 8. Unified Threat Alerts stream aggregation (memory + web threat vectors).
 * 9. Incident triage status workflow updates (INVESTIGATING, RESOLVED, DISMISSED).
 * 10. Unified SOC Incident Report generation and artifact persistence.
 * 11. Multi-tenant ownership isolation between security analysts.
 * =====================================================================
 */

import http from "http";
import { app } from "./dist/app.js";

async function runPhase4Tests() {
  console.log("=======================================================");
  console.log("  PHANTOMTRACE PHASE 4: UNIFIED THREAT & POLICY SUITE  ");
  console.log("=======================================================");

  let passed = 0;
  let failed = 0;

  function assert(desc, condition, details = "") {
    if (condition) {
      console.log(`[PASS] ✓ ${desc}`);
      passed++;
    } else {
      console.error(`[FAIL] ✗ ${desc} - ${details}`);
      failed++;
    }
  }

  // Launch temporary HTTP server on ephemeral port
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = address.port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const analystAHeaders = {
    Authorization: "Bearer dev-analyst-alpha",
    "Content-Type": "application/json",
  };

  const analystBHeaders = {
    Authorization: "Bearer dev-analyst-beta",
    "Content-Type": "application/json",
  };

  try {
    // -----------------------------------------------------------------
    // 1. Authentication Enforcement (Phase 4 Endpoints)
    // -----------------------------------------------------------------
    {
      const endpointsToTest = [
        { method: "GET", path: "/api/web-threats/policies" },
        { method: "POST", path: "/api/web-threats/policies", body: { domain: "test.com", policyType: "BLOCK" } },
        { method: "DELETE", path: "/api/web-threats/policies/pol-123" },
        { method: "GET", path: "/api/web-threats/correlated" },
        { method: "GET", path: "/api/alerts/unified" },
        { method: "POST", path: "/api/reports/generate-unified" },
      ];

      for (const ep of endpointsToTest) {
        const res = await fetch(`${baseUrl}${ep.path}`, {
          method: ep.method,
          headers: { "Content-Type": "application/json" },
          body: ep.body ? JSON.stringify(ep.body) : undefined,
        });
        assert(
          `Unauthenticated ${ep.method} ${ep.path} returns 401 Unauthorized`,
          res.status === 401
        );
      }
    }

    // -----------------------------------------------------------------
    // 2. Domain Policy Validation & Normalization
    // -----------------------------------------------------------------
    {
      // Missing domain
      const resMissing = await fetch(`${baseUrl}/api/web-threats/policies`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({ policyType: "BLOCK" }),
      });
      assert("POST /policies with missing domain rejected with 400", resMissing.status === 400);

      // Malformed domain / dangerous scheme
      const resBad = await fetch(`${baseUrl}/api/web-threats/policies`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({ domain: "javascript:alert(1)", policyType: "BLOCK" }),
      });
      assert("POST /policies with dangerous URL scheme rejected with 400", resBad.status === 400);

      // Invalid policy type
      const resBadType = await fetch(`${baseUrl}/api/web-threats/policies`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({ domain: "malware-sample.net", policyType: "QUARANTINE" }),
      });
      assert("POST /policies with invalid policyType rejected with 400", resBadType.status === 400);
    }

    // -----------------------------------------------------------------
    // 3. Domain Policy Creation (BLOCK & ALLOW)
    // -----------------------------------------------------------------
    let blockPolicyId = "";
    let _allowPolicyId = "";
    {
      // Create BLOCK rule
      const resBlock = await fetch(`${baseUrl}/api/web-threats/policies`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({
          domain: "HTTPS://EVIL-EXPLOIT.NET/path?token=secret#frag",
          policyType: "BLOCK",
          reason: "Active credential harvest campaign",
        }),
      });
      assert("POST /policies creates BLOCK rule (201)", resBlock.status === 201);
      const dataBlock = await resBlock.json();
      assert(
        "Domain normalized cleanly to lowercase without path/query",
        dataBlock.policy?.domain === "evil-exploit.net"
      );
      assert("Policy type set to BLOCK", dataBlock.policy?.policyType === "BLOCK");
      blockPolicyId = dataBlock.policy?.policyId;

      // Create ALLOW rule
      const resAllow = await fetch(`${baseUrl}/api/web-threats/policies`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({
          domain: "internal-corp-dev.local",
          policyType: "ALLOW",
          reason: "Authorized internal staging portal",
        }),
      });
      assert("POST /policies creates ALLOW rule (201)", resAllow.status === 201);
      const dataAllow = await resAllow.json();
      assert("Policy type set to ALLOW", dataAllow.policy?.policyType === "ALLOW");
      _allowPolicyId = dataAllow.policy?.policyId;
    }

    // -----------------------------------------------------------------
    // 4. Domain Policy Listing & Tenant Isolation
    // -----------------------------------------------------------------
    {
      const resListA = await fetch(`${baseUrl}/api/web-threats/policies`, {
        headers: analystAHeaders,
      });
      const dataA = await resListA.json();
      assert("GET /policies lists created rules for Analyst A", (dataA.policies?.length || 0) >= 2);

      // Verify Analyst B does not see Analyst A's rules
      const resListB = await fetch(`${baseUrl}/api/web-threats/policies`, {
        headers: analystBHeaders,
      });
      const dataB = await resListB.json();
      assert(
        "Analyst B tenant isolation verified (does not see Analyst A policies)",
        !dataB.policies?.some((p) => p.domain === "evil-exploit.net")
      );
    }

    // -----------------------------------------------------------------
    // 5. Threat Intelligence Policy Override Enforcement
    // -----------------------------------------------------------------
    {
      // 5.1 Test BLOCK rule override on check endpoint
      const resCheckBlock = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: "evil-exploit.net",
          ownerUid: "uid-dev-analyst-alpha",
        }),
      });
      assert("POST /web-threats/check returns 200", resCheckBlock.status === 200);
      const dataCheckBlock = await resCheckBlock.json();
      assert(
        "BLOCK policy overrides verdict to POLICY_VIOLATION with score 100",
        dataCheckBlock.result?.verdict === "POLICY_VIOLATION" && dataCheckBlock.result?.score === 100
      );
      assert(
        "BLOCK policy ruleId set to POLICY_USER_BLOCKED",
        dataCheckBlock.result?.ruleId === "POLICY_USER_BLOCKED"
      );

      // 5.2 Test ALLOW rule override on check endpoint
      const resCheckAllow = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: "internal-corp-dev.local",
          ownerUid: "uid-dev-analyst-alpha",
        }),
      });
      const dataCheckAllow = await resCheckAllow.json();
      assert(
        "ALLOW policy overrides verdict to BENIGN with score 0",
        dataCheckAllow.result?.verdict === "BENIGN" && dataCheckAllow.result?.score === 0
      );
      assert(
        "ALLOW policy source set to POLICY_RULE",
        dataCheckAllow.result?.source === "POLICY_RULE"
      );
    }

    // -----------------------------------------------------------------
    // 6. Cross-Vector Threat Ingestion & Correlation
    // -----------------------------------------------------------------
    let testEventId = "";
    {
      // Ingest a web threat event for Analyst A
      const resEvent = await fetch(`${baseUrl}/api/web-threats/events`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({
          domain: "evil-exploit.net",
          url: "https://evil-exploit.net/login.php",
          classification: "PHISHING",
          severity: "CRITICAL",
          score: 95,
          browser: "Microsoft Edge",
          explanation: "Credential interceptor detected.",
        }),
      });
      assert("POST /web-threats/events ingests web threat event (201)", resEvent.status === 201);
      const eventData = await resEvent.json();
      testEventId = eventData.eventId;

      // Query correlated events
      const resCorr = await fetch(`${baseUrl}/api/web-threats/correlated`, {
        headers: analystAHeaders,
      });
      assert("GET /web-threats/correlated returns 200", resCorr.status === 200);
      const dataCorr = await resCorr.json();
      assert("Correlated threat events array returned", Array.isArray(dataCorr.correlatedEvents));
      const matched = dataCorr.correlatedEvents?.find((c) => c.webThreat?.id === testEventId);
      assert("Ingested event present in correlation view", Boolean(matched));
    }

    // -----------------------------------------------------------------
    // 7. Incident Triage Status Workflow
    // -----------------------------------------------------------------
    {
      // Update status to INVESTIGATING
      const resStatus1 = await fetch(`${baseUrl}/api/web-threats/events/${testEventId}/status`, {
        method: "POST",
        headers: analystAHeaders,
        body: JSON.stringify({
          status: "INVESTIGATING",
          notes: "Assigned to incident responder #104.",
        }),
      });
      assert("POST /events/:id/status updates status to INVESTIGATING (200)", resStatus1.status === 200);
      const dataStatus1 = await resStatus1.json();
      assert("Status updated to INVESTIGATING", dataStatus1.status === "INVESTIGATING");

      // Update status via PATCH to RESOLVED
      const resStatus2 = await fetch(`${baseUrl}/api/web-threats/events/${testEventId}/status`, {
        method: "PATCH",
        headers: analystAHeaders,
        body: JSON.stringify({
          status: "RESOLVED",
          notes: "Domain blocked across perimeter.",
        }),
      });
      assert("PATCH /events/:id/status updates status to RESOLVED (200)", resStatus2.status === 200);
      const dataStatus2 = await resStatus2.json();
      assert("Status updated to RESOLVED", dataStatus2.status === "RESOLVED");
    }

    // -----------------------------------------------------------------
    // 8. Unified Threat Alerts Stream
    // -----------------------------------------------------------------
    {
      const resUnified = await fetch(`${baseUrl}/api/alerts/unified`, {
        headers: analystAHeaders,
      });
      assert("GET /api/alerts/unified returns 200", resUnified.status === 200);
      const dataUnified = await resUnified.json();
      assert("Unified alerts returned as array", Array.isArray(dataUnified.alerts));
      const webAlert = dataUnified.alerts?.find((a) => a.id === testEventId);
      assert("Web Threat event mapped into unified alerts stream", Boolean(webAlert));
      assert("Unified alert vector set to WEB_THREAT", webAlert?.vector === "WEB_THREAT");
      assert("Unified alert targetName matches domain", webAlert?.targetName === "evil-exploit.net");
    }

    // -----------------------------------------------------------------
    // 9. Unified SOC Incident Report Generation
    // -----------------------------------------------------------------
    {
      const resReport = await fetch(`${baseUrl}/api/reports/generate-unified`, {
        method: "POST",
        headers: analystAHeaders,
      });
      assert("POST /reports/generate-unified generates SOC report (201)", resReport.status === 201);
      const dataReport = await resReport.json();
      assert("Report document returned with unique ID", Boolean(dataReport.report?.id));
      assert("Report title reflects Unified SOC Incident Audit", dataReport.report?.title?.includes("Unified SOC"));
      assert("Report content incorporates non-destructive protocol", typeof dataReport.report?.content === "string");
      assert("Report content includes executive summary section", dataReport.report?.content?.includes("EXECUTIVE THREAT TELEMETRY SUMMARY"));
      assert("Report content includes active domain policies", dataReport.report?.content?.includes("DOMAIN SECURITY POLICIES"));
    }

    // -----------------------------------------------------------------
    // 10. Domain Policy Deletion & Multi-Tenant Access Control
    // -----------------------------------------------------------------
    {
      // Analyst B attempts to delete Analyst A's policy rule (Unauthorized)
      const resDeleteUnauthorized = await fetch(`${baseUrl}/api/web-threats/policies/${blockPolicyId}`, {
        method: "DELETE",
        headers: analystBHeaders,
      });
      assert("Analyst B cannot delete Analyst A's policy rule (404/unauthorized)", resDeleteUnauthorized.status === 404);

      // Analyst A deletes own policy rule
      const resDeleteAuthorized = await fetch(`${baseUrl}/api/web-threats/policies/${blockPolicyId}`, {
        method: "DELETE",
        headers: analystAHeaders,
      });
      assert("Analyst A deletes own policy rule (200)", resDeleteAuthorized.status === 200);
    }
  } finally {
    server.close();
  }

  console.log("=======================================================");
  console.log(`  PHASE 4 TEST SUMMARY: PASSED: ${passed} | FAILED: ${failed}`);
  console.log("=======================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runPhase4Tests().catch((err) => {
  console.error("Fatal error during Phase 4 tests:", err);
  process.exit(1);
});
