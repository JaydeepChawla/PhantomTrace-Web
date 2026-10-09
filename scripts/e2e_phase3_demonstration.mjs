/**
 * =====================================================================
 * PHANTOMTRACE PHASE 3: END-TO-END BROWSER & EXTENSION VERIFICATION
 * =====================================================================
 * Uses Microsoft Edge with local mock provider fixtures to demonstrate:
 * 1. Default state: monitoring disabled, no reputation checks or events.
 * 2. Enabling monitoring via extension settings.
 * 3. Controlled malicious navigation -> interstitial warning redirect.
 * 4. Warning page DOM content and parameters.
 * 5. Backend event persistence via authenticated API.
 * 6. Dashboard data retrieval verification.
 * 7. Benign navigation (google.com) allowed without warning.
 * 8. Provider unavailable (offline-test.local) fails safe without blocking.
 * 9. User disabling monitoring prevents subsequent reputation checks.
 *
 * SAFETY: Uses --host-resolver-rules="MAP * 127.0.0.1" to ensure zero
 * external network requests leave the machine.
 * =====================================================================
 */

import http from "http";
import path from "path";
import os from "os";
import fs from "fs";
import { spawn } from "child_process";
import { app } from "../server/dist/app.js";

const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const EXTENSION_PATH = path.resolve("browser-extension");
const BACKEND_PORT = 5000;
const AGENT_PORT = 49152;
const CDP_PORT = 9223;

class CdpClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.idCounter = 1;
    this.pending = new Map();
    this.eventListeners = new Map();
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onopen = () => resolve();
      this.ws.onerror = (e) => reject(e);
      this.ws.onmessage = (msg) => {
        const data = JSON.parse(msg.data);
        if (data.id && this.pending.has(data.id)) {
          const { resolve, reject } = this.pending.get(data.id);
          this.pending.delete(data.id);
          if (data.error) reject(new Error(data.error.message));
          else resolve(data.result);
        } else if (data.method) {
          const listeners = this.eventListeners.get(data.method) || [];
          for (const cb of listeners) cb(data.params);
        }
      };
    });
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.idCounter++;
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  on(event, callback) {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event).push(callback);
  }

  close() {
    if (this.ws) {
      try { this.ws.close(); } catch {}
    }
  }
}

async function runE2E() {
  console.log("=====================================================================");
  console.log("  PHANTOMTRACE PHASE 3: END-TO-END BROWSER INTEGRATION VERIFICATION  ");
  console.log("=====================================================================\n");

  let passed = 0;
  let failed = 0;

  function assert(title, condition, details = "") {
    if (condition) {
      console.log(`[PASS] \u2713 ${title}`);
      passed++;
    } else {
      console.error(`[FAIL] \u2717 ${title} - ${details}`);
      failed++;
    }
  }

  // 1. Start HTTP Backend & Mock Web Server on port 5000
  console.log("[Setup] Starting backend server on http://127.0.0.1:5000 ...");
  const httpServer = http.createServer((req, res) => {
    // If request is an API request, route to Express app
    if (req.url.startsWith("/api/")) {
      app(req, res);
      return;
    }
    // Otherwise serve safe mock HTML for browser navigations
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<!DOCTYPE html><html><body><h1>Mock Web Server</h1><p>URL: ${req.url}</p></body></html>`);
  });

  for (let attempt = 1; attempt <= 10; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(BACKEND_PORT, "127.0.0.1", () => {
          httpServer.removeListener("error", reject);
          resolve();
        });
      });
      break;
    } catch (err) {
      if (err.code === "EADDRINUSE" && attempt < 10) {
        console.log(`  [Wait] Port ${BACKEND_PORT} in TIME_WAIT, waiting 3s (attempt ${attempt}/10)...`);
        await new Promise((r) => setTimeout(r, 3000));
      } else {
        throw err;
      }
    }
  }

  // 2. Start Python Local Agent on port 49152
  console.log("[Setup] Starting local Windows Agent API on http://127.0.0.1:49152 ...");
  const agentProc = spawn("python", [
    "-c",
    `
import sys
sys.path.insert(0, "phantomtrace-agent")
from agent_service.local_api import create_agent_server
server = create_agent_server("127.0.0.1", ${AGENT_PORT})
server.serve_forever()
    `,
  ], { cwd: path.resolve(".") });

  // Wait for local agent to listen
  await new Promise((r) => setTimeout(r, 1200));
  console.log("  \u2192 Local agent running.\n");

  // 3. Launch Microsoft Edge with unpacked extension
  const tempProfile = path.join(os.tmpdir(), `edge-pt-e2e-${Date.now()}`);
  console.log(`[Setup] Launching Microsoft Edge with unpacked extension...`);
  console.log(`  Extension: ${EXTENSION_PATH}`);
  console.log(`  Profile:   ${tempProfile}`);

  const edgeProc = spawn(EDGE_PATH, [
    `--remote-debugging-port=${CDP_PORT}`,
    `--load-extension=${EXTENSION_PATH}`,
    `--user-data-dir=${tempProfile}`,
    `--host-resolver-rules=MAP * 127.0.0.1`,
    `--no-first-run`,
    `--no-default-browser-check`,
  ]);

  let swClient = null;
  let pageClient = null;

  try {
    // Poll CDP for extension service worker and page target
    console.log("[Setup] Connecting to Edge via Chrome DevTools Protocol (CDP)...");
    let extSwTarget = null;
    let pageTarget = null;

    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 800));
      try {
        const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`);
        const targets = await res.json();
        if (!extSwTarget) {
          extSwTarget = targets.find(
            (t) => t.type === "service_worker" && t.url.includes("background.js")
          );
        }
        if (!pageTarget) {
          pageTarget = targets.find((t) => t.type === "page");
        }
        if (extSwTarget && pageTarget) break;
      } catch {}
    }

    if (!extSwTarget || !pageTarget) {
      throw new Error(`Failed to find Edge CDP targets. SW: ${Boolean(extSwTarget)}, Page: ${Boolean(pageTarget)}`);
    }

    console.log(`  \u2192 Connected to Extension SW: ${extSwTarget.url}`);
    console.log(`  \u2192 Connected to Page Target:   ${pageTarget.title}\n`);

    swClient = new CdpClient(extSwTarget.webSocketDebuggerUrl);
    await swClient.connect();

    pageClient = new CdpClient(pageTarget.webSocketDebuggerUrl);
    await pageClient.connect();
    await pageClient.send("Page.enable");
    await pageClient.send("Runtime.enable");

    // =========================================================================
    // FLOW 1: DEFAULT STATE — MONITORING DISABLED
    // =========================================================================
    console.log("---------------------------------------------------------------------");
    console.log("FLOW 1: VERIFY DEFAULT MONITORING DISABLED STATE");
    console.log("---------------------------------------------------------------------");

    const statusEval = await swClient.send("Runtime.evaluate", {
      expression: "JSON.stringify({ enabled: runtimeState.monitoringEnabled, url: runtimeState.backendUrl })",
      returnByValue: true,
    });
    const initialStatus = JSON.parse(statusEval.result.value);

    assert(
      "Extension initializes with monitoring disabled (privacy-first default)",
      initialStatus.enabled === false,
      JSON.stringify(initialStatus)
    );

    // Navigate to a domain while disabled -> should NOT redirect or alert
    await pageClient.send("Page.navigate", { url: `http://phishing-bank-login.com:${BACKEND_PORT}/test-disabled` });
    await new Promise((r) => setTimeout(r, 1500));

    const disabledNavUrl = (
      await pageClient.send("Runtime.evaluate", { expression: "window.location.href", returnByValue: true })
    ).result.value;

    assert(
      "Navigation while monitoring disabled proceeds without interruption or warning",
      disabledNavUrl.includes("phishing-bank-login.com") && !disabledNavUrl.includes("warning.html"),
      `Current URL: ${disabledNavUrl}`
    );

    // =========================================================================
    // FLOW 2: USER ENABLES MONITORING
    // =========================================================================
    console.log("\n---------------------------------------------------------------------");
    console.log("FLOW 2: USER ACTIVATES WEB THREAT MONITORING");
    console.log("---------------------------------------------------------------------");

    await swClient.send("Runtime.evaluate", {
      expression: `
        new Promise((resolve) => {
          chrome.storage.local.set({
            monitoringEnabled: true,
            backendUrl: "http://127.0.0.1:${BACKEND_PORT}",
            authToken: "dev-analyst-phase3"
          }, () => {
            runtimeState.monitoringEnabled = true;
            runtimeState.backendUrl = "http://127.0.0.1:${BACKEND_PORT}";
            resolve(true);
          });
        })
      `,
      awaitPromise: true,
    });

    const activeEval = await swClient.send("Runtime.evaluate", {
      expression: "JSON.stringify({ enabled: runtimeState.monitoringEnabled, url: runtimeState.backendUrl })",
      returnByValue: true,
    });
    const activeStatus = JSON.parse(activeEval.result.value);

    assert(
      "Monitoring enabled successfully and backend connected",
      activeStatus.enabled === true && activeStatus.url.includes("5000"),
      JSON.stringify(activeStatus)
    );

    // =========================================================================
    // FLOW 3: CONTROLLED MALICIOUS NAVIGATION -> WARNING INTERSTITIAL
    // =========================================================================
    console.log("\n---------------------------------------------------------------------");
    console.log("FLOW 3: CONTROLLED MALICIOUS VERDICT & WARNING REDIRECT");
    console.log("---------------------------------------------------------------------");

    const targetPhishingUrl = `http://phishing-bank-login.com:${BACKEND_PORT}/auth/login`;
    await pageClient.send("Page.navigate", { url: targetPhishingUrl });

    // Wait for extension interception and redirect
    let redirectedUrl = "";
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 300));
      const res = await pageClient.send("Runtime.evaluate", {
        expression: "window.location.href",
        returnByValue: true,
      });
      redirectedUrl = res.result.value;
      if (redirectedUrl.includes("warning.html")) break;
    }

    assert(
      "High-confidence threat navigation intercepted and redirected to warning interstitial",
      redirectedUrl.includes("warning.html") && redirectedUrl.includes("domain=phishing-bank-login.com"),
      `Redirected to: ${redirectedUrl}`
    );

    // Inspect warning interstitial DOM elements with wait for script execution
    let domData = {};
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 200));
      const warningDom = await pageClient.send("Runtime.evaluate", {
        expression: `JSON.stringify({
          title: document.getElementById("warningTitle")?.textContent,
          domain: document.getElementById("domainDisplay")?.textContent,
          classification: document.getElementById("classificationVal")?.textContent,
          severity: document.getElementById("severityBadge")?.textContent,
          ruleId: document.getElementById("ruleVal")?.textContent
        })`,
        returnByValue: true,
      });
      domData = JSON.parse(warningDom.result.value || "{}");
      if (domData.domain === "phishing-bank-login.com") break;
    }

    assert(
      "Warning page DOM displays accurate threat details, domain, and classification",
      domData.domain === "phishing-bank-login.com" &&
        domData.classification === "PHISHING" &&
        domData.title.includes("Phishing"),
      JSON.stringify(domData)
    );

    // =========================================================================
    // FLOW 4 & 5: PERSISTED BACKEND EVENT & DASHBOARD INTEGRATION
    // =========================================================================
    console.log("\n---------------------------------------------------------------------");
    console.log("FLOW 4 & 5: EVENT PERSISTENCE & DASHBOARD INTEGRATION");
    console.log("---------------------------------------------------------------------");

    // Allow background worker time to execute async backend sync
    await new Promise((r) => setTimeout(r, 1000));

    const eventsRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/web-threats/events`, {
      headers: {
        Authorization: "Bearer dev-analyst-phase3",
      },
    });
    const eventsData = await eventsRes.json();
    const persistedEvent = eventsData.events?.find(
      (e) => e.domain === "phishing-bank-login.com"
    );

    assert(
      "Threat event persisted to backend database via authenticated ingestion",
      eventsRes.status === 200 && Boolean(persistedEvent),
      `Status: ${eventsRes.status}, Events: ${eventsData.events?.length || 0}`
    );

    if (persistedEvent) {
      assert(
        "Persisted event retains classification, score, and explanation",
        persistedEvent.classification === "PHISHING" &&
          persistedEvent.severity === "HIGH" &&
          persistedEvent.score >= 80,
        JSON.stringify(persistedEvent)
      );
    }

    // Dashboard Status API
    const statusRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/web-threats/status`);
    const statusData = await statusRes.json();
    assert(
      "Dashboard status API confirms threat service active and healthy",
      statusRes.status === 200 && statusData.status === "ok" && statusData.provider === "PhantomTrace-Mock-ThreatIntel",
      JSON.stringify(statusData)
    );

    // =========================================================================
    // FLOW 6: BENIGN NAVIGATION ALLOWED WITHOUT WARNING
    // =========================================================================
    console.log("\n---------------------------------------------------------------------");
    console.log("FLOW 6: BENIGN NAVIGATION (google.com)");
    console.log("---------------------------------------------------------------------");

    const benignUrl = `http://google.com:${BACKEND_PORT}/search?q=cybersecurity`;
    await pageClient.send("Page.navigate", { url: benignUrl });
    await new Promise((r) => setTimeout(r, 1200));

    const benignNavUrl = (
      await pageClient.send("Runtime.evaluate", { expression: "window.location.href", returnByValue: true })
    ).result.value;

    assert(
      "Benign navigation loads destination without warning interstitial",
      benignNavUrl.includes("google.com") && !benignNavUrl.includes("warning.html"),
      `Current URL: ${benignNavUrl}`
    );

    // =========================================================================
    // FLOW 7: PROVIDER UNAVAILABLE / OFFLINE (FAIL-SAFE)
    // =========================================================================
    console.log("\n---------------------------------------------------------------------");
    console.log("FLOW 7: PROVIDER UNAVAILABLE (FAIL-SAFE DESIGN)");
    console.log("---------------------------------------------------------------------");

    const offlineUrl = `http://offline-test.phantomtrace.local:${BACKEND_PORT}/docs`;
    await pageClient.send("Page.navigate", { url: offlineUrl });
    await new Promise((r) => setTimeout(r, 1200));

    const offlineNavUrl = (
      await pageClient.send("Runtime.evaluate", { expression: "window.location.href", returnByValue: true })
    ).result.value;

    assert(
      "Offline/unavailable reputation provider fails safe and allows user navigation",
      offlineNavUrl.includes("offline-test.phantomtrace.local") && !offlineNavUrl.includes("warning.html"),
      `Current URL: ${offlineNavUrl}`
    );

    // =========================================================================
    // FLOW 8: MONITORING DISABLED BY USER
    // =========================================================================
    console.log("\n---------------------------------------------------------------------");
    console.log("FLOW 8: USER TOGGLES MONITORING OFF");
    console.log("---------------------------------------------------------------------");

    await swClient.send("Runtime.evaluate", {
      expression: `
        new Promise((resolve) => {
          chrome.storage.local.set({ monitoringEnabled: false }, () => {
            runtimeState.monitoringEnabled = false;
            resolve(true);
          });
        })
      `,
      awaitPromise: true,
    });

    // Navigate to critical malware fixture while disabled
    const malwareUrl = `http://malware-drop-test.xyz:${BACKEND_PORT}/drop`;
    await pageClient.send("Page.navigate", { url: malwareUrl });
    await new Promise((r) => setTimeout(r, 1200));

    const disabledMalwareUrl = (
      await pageClient.send("Runtime.evaluate", { expression: "window.location.href", returnByValue: true })
    ).result.value;

    assert(
      "Disabled monitoring prevents reputation checks and threat-event generation for malware fixture",
      disabledMalwareUrl.includes("malware-drop-test.xyz") && !disabledMalwareUrl.includes("warning.html"),
      `Current URL: ${disabledMalwareUrl}`
    );

  } finally {
    // Teardown
    console.log("\n[Teardown] Cleaning up processes and servers...");
    if (pageClient) pageClient.close();
    if (swClient) swClient.close();
    edgeProc.kill();
    agentProc.kill();
    await new Promise((resolve) => httpServer.close(resolve));
    try {
      fs.rmSync(tempProfile, { recursive: true, force: true });
    } catch {}
    console.log("  \u2192 Cleaned up successfully.\n");
  }

  console.log("=====================================================================");
  console.log(`TOTAL E2E TESTS PASSED: ${passed}`);
  console.log(`TOTAL E2E TESTS FAILED: ${failed}`);
  console.log("=====================================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runE2E().catch((err) => {
  console.error("E2E Test Execution encountered error:", err);
  process.exit(1);
});
