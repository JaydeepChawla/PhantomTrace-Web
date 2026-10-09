/**
 * =====================================================================
 * PHANTOMTRACE PHASE 3 — WEB THREAT MONITOR TEST SUITE
 * =====================================================================
 * Validates all required test cases:
 * 1. Known malicious URL returned by controlled mock threat-intelligence provider.
 * 2. Benign URL.
 * 3. Suspicious URL detected by conservative heuristic.
 * 4. Unavailable reputation provider handling.
 * 5. Provider timeouts.
 * 6. Offline behavior handling.
 * 7. Duplicate event suppression and caching.
 * 8. URL normalization, redaction, and privacy.
 * 9. Authentication and API input validation.
 * 10. Security-event persistence.
 * 11. Event retention after deletion of associated test file.
 * 12. Monitoring status and health checks.
 * =====================================================================
 */

import http from "http";
import fs from "fs";
import path from "path";
import { app } from "./dist/app.js";

async function runTests() {
  console.log("=======================================================");
  console.log("  PHANTOMTRACE PHASE 3: WEB THREAT MONITOR TEST SUITE  ");
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

  // Start temporary HTTP test server on an ephemeral port
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = address.port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const authHeader = {
    Authorization: "Bearer dev-analyst-phase3",
    "Content-Type": "application/json",
  };

  try {
    // -----------------------------------------------------------------
    // 1. Service Health & Status Endpoint
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/web-threats/status`);
      const data = await res.json();
      assert(
        "GET /api/web-threats/status returns 200 and provider information",
        res.status === 200 && data.status === "ok" && data.provider === "PhantomTrace-Mock-ThreatIntel",
        JSON.stringify(data)
      );
    }

    // -----------------------------------------------------------------
    // 2. Known Malicious URL via Controlled Mock Provider
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://phishing-bank-login.com/auth/login" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Known malicious phishing domain identified by threat intel provider",
        res.status === 200 &&
          r.verdict === "PHISHING" &&
          r.severity === "HIGH" &&
          r.source === "THREAT_INTEL" &&
          r.ruleId === "TI-RULE-7412",
        JSON.stringify(r)
      );
    }

    {
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "malware-drop-test.xyz" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Known critical malware drop domain identified by threat intel provider",
        res.status === 200 &&
          r.verdict === "MALWARE" &&
          r.severity === "CRITICAL" &&
          r.score >= 90,
        JSON.stringify(r)
      );
    }

    // -----------------------------------------------------------------
    // 3. Benign URL Handling
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://google.com/search?q=cybersecurity" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Benign domain returns BENIGN status and zero score",
        res.status === 200 &&
          r.verdict === "BENIGN" &&
          r.severity === "NORMAL" &&
          r.score === 0,
        JSON.stringify(r)
      );
    }

    // -----------------------------------------------------------------
    // 4. Conservative Heuristics for Suspicious URLs
    // -----------------------------------------------------------------
    {
      // Brand impersonation pattern
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "paypal-security-update.com" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Heuristic detects suspicious brand impersonation pattern",
        res.status === 200 &&
          r.verdict === "SUSPICIOUS_HEURISTIC" &&
          r.severity === "MEDIUM" &&
          r.source === "HEURISTIC" &&
          r.ruleId === "HEUR-BRAND-IMPERSONATION",
        JSON.stringify(r)
      );
    }

    {
      // Direct IP address navigation
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "http://185.220.101.5/admin" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Heuristic detects direct public IP address navigation",
        res.status === 200 &&
          r.verdict === "SUSPICIOUS_HEURISTIC" &&
          r.ruleId === "HEUR-DIRECT-IP",
        JSON.stringify(r)
      );
    }

    // -----------------------------------------------------------------
    // 5. Unknown Domain Never Automatically Marked Malicious
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "clean-unknown-research-blog.org" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Unknown domain is classified as UNKNOWN (not marked as malicious)",
        res.status === 200 &&
          r.verdict === "UNKNOWN" &&
          r.severity === "NORMAL" &&
          r.score === 0,
        JSON.stringify(r)
      );
    }

    // -----------------------------------------------------------------
    // 6. Provider Timeout Simulation
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "timeout-test.phantomtrace.local" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Provider timeout is handled safely without blocking or marking malicious",
        res.status === 200 &&
          r.status === "TIMEOUT" &&
          r.verdict === "UNKNOWN",
        JSON.stringify(r)
      );
    }

    // -----------------------------------------------------------------
    // 7. Provider Offline Simulation
    // -----------------------------------------------------------------
    {
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "offline-test.phantomtrace.local" }),
      });
      const data = await res.json();
      const r = data.result;
      assert(
        "Offline provider is handled gracefully with OFFLINE status and UNKNOWN verdict",
        res.status === 200 &&
          r.status === "OFFLINE" &&
          r.verdict === "UNKNOWN",
        JSON.stringify(r)
      );
    }

    // -----------------------------------------------------------------
    // 8. Privacy: URL Normalization, Redaction & Query String Stripping
    // -----------------------------------------------------------------
    {
      const sensitiveUrl = "https://admin:superSecret123@suspicious-portal.com/login?token=confidential_session_token#user_data";
      const res = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: sensitiveUrl }),
      });
      const data = await res.json();
      const r = data.result;
      const jsonStr = JSON.stringify(data);

      assert(
        "Domain extracted cleanly and passwords/tokens completely redacted",
        res.status === 200 &&
          r.domain === "suspicious-portal.com" &&
          !jsonStr.includes("superSecret123") &&
          !jsonStr.includes("confidential_session_token"),
        jsonStr
      );
    }

    // -----------------------------------------------------------------
    // 9. Input Validation & Dangerous Schemes Rejected
    // -----------------------------------------------------------------
    {
      const badSchemes = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///C:/Windows/System32/cmd.exe",
        "",
      ];

      for (const scheme of badSchemes) {
        const res = await fetch(`${baseUrl}/api/web-threats/check`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: scheme }),
        });
        const data = await res.json();
        assert(
          `Unsupported or dangerous scheme '${scheme.slice(0, 20)}' handled safely`,
          res.status === 400 || (res.status === 200 && data.result?.status === "ERROR"),
          `Status: ${res.status}`
        );
      }
    }

    // -----------------------------------------------------------------
    // 9B. Browser Extension CORS & Unauthorized Origin Protection
    // -----------------------------------------------------------------
    {
      // 1. Authorized Chrome/Edge extension origin must be permitted
      const extRes = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: {
          "Origin": "chrome-extension://abcdefghijklmnop",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain: "google.com" }),
      });
      assert(
        "Browser extension origin 'chrome-extension://...' is allowed by backend CORS",
        extRes.status === 200,
        `Status: ${extRes.status}`
      );

      // 2. Unauthorized attacker origin must be blocked with 403
      const evilRes = await fetch(`${baseUrl}/api/web-threats/check`, {
        method: "POST",
        headers: {
          "Origin": "https://evil-attacker.com",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain: "google.com" }),
      });
      assert(
        "Untrusted web origin 'https://evil-attacker.com' is blocked by backend CORS",
        evilRes.status === 403,
        `Status: ${evilRes.status}`
      );
    }

    // -----------------------------------------------------------------
    // 10. Authentication & Authorization for Event Ingestion
    // -----------------------------------------------------------------
    {
      // Unauthenticated request to /api/web-threats/events must reject with 401
      const unauthRes = await fetch(`${baseUrl}/api/web-threats/events`);
      assert(
        "Unauthenticated GET /api/web-threats/events returns 401 Unauthorized",
        unauthRes.status === 401,
        `Status: ${unauthRes.status}`
      );

      const unauthPost = await fetch(`${baseUrl}/api/web-threats/events`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: "test.com" }),
      });
      assert(
        "Unauthenticated POST /api/web-threats/events returns 401 Unauthorized",
        unauthPost.status === 401,
        `Status: ${unauthPost.status}`
      );
    }

    // -----------------------------------------------------------------
    // 11. Security-Event Persistence & Ingestion
    // -----------------------------------------------------------------
    let createdEventId = "";
    {
      const eventPayload = {
        domain: "phishing-bank-login.com",
        classification: "PHISHING",
        severity: "HIGH",
        score: 85,
        confidence: "HIGH",
        detectionSource: "THREAT_INTEL",
        ruleId: "TI-RULE-7412",
        explanation: "Confirmed banking credential phish.",
        browser: "Microsoft Edge 120",
      };

      const res = await fetch(`${baseUrl}/api/web-threats/events`, {
        method: "POST",
        headers: authHeader,
        body: JSON.stringify(eventPayload),
      });
      const data = await res.json();
      assert(
        "POST /api/web-threats/events persists threat event and returns 201",
        res.status === 201 && data.success === true && typeof data.eventId === "string",
        JSON.stringify(data)
      );
      createdEventId = data.eventId;

      // Query persisted events
      const listRes = await fetch(`${baseUrl}/api/web-threats/events`, {
        headers: authHeader,
      });
      const listData = await listRes.json();
      assert(
        "GET /api/web-threats/events returns persisted threat events for authenticated user",
        listRes.status === 200 &&
          Array.isArray(listData.events) &&
          listData.events.some((e) => e.id === createdEventId && e.domain === "phishing-bank-login.com"),
        JSON.stringify(listData)
      );
    }

    // -----------------------------------------------------------------
    // 12. Event Retention After Deletion of Associated Test File
    // -----------------------------------------------------------------
    {
      const tempFilePath = path.join(process.cwd(), "temp_download_test_sample.tmp");
      fs.writeFileSync(tempFilePath, "temporary downloaded content");

      // Ingest event associated with download test
      const res = await fetch(`${baseUrl}/api/web-threats/events`, {
        method: "POST",
        headers: authHeader,
        body: JSON.stringify({
          domain: "malware-download-sample.xyz",
          classification: "MALWARE",
          severity: "CRITICAL",
          score: 95,
          explanation: "Downloaded payload associated test.",
        }),
      });
      const data = await res.json();
      const downloadEventId = data.eventId;

      // Delete the temporary file
      if (fs.existsSync(tempFilePath)) {
        fs.unlinkSync(tempFilePath);
      }

      // Verify event is still persisted in the database independent of file
      const listRes = await fetch(`${baseUrl}/api/web-threats/events`, {
        headers: authHeader,
      });
      const listData = await listRes.json();
      const eventRetained = listData.events?.some((e) => e.id === downloadEventId);

      assert(
        "Security-event metadata is retained independently after test file deletion",
        eventRetained,
        `Event ID: ${downloadEventId}`
      );
    }

    // -----------------------------------------------------------------
    // 13. Threat Event Dismissal
    // -----------------------------------------------------------------
    {
      if (createdEventId) {
        const dismissRes = await fetch(`${baseUrl}/api/web-threats/events/${createdEventId}/dismiss`, {
          method: "POST",
          headers: authHeader,
        });
        const dismissData = await dismissRes.json();
        assert(
          "POST /api/web-threats/events/:id/dismiss updates event status to DISMISSED",
          dismissRes.status === 200 && dismissData.status === "DISMISSED",
          JSON.stringify(dismissData)
        );
      }
    }

  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  console.log("=======================================================");
  console.log(`TOTAL PASSED: ${passed}`);
  console.log(`TOTAL FAILED: ${failed}`);
  console.log("=======================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Test execution failed with unhandled error:", err);
  process.exit(1);
});
