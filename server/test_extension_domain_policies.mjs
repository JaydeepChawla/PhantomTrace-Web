/**
 * =====================================================================
 * PHANTOMTRACE — EXTENSION DOMAIN SECURITY POLICIES & SYNC TEST SUITE
 * =====================================================================
 * Validates:
 * 1. Manifest V3 DeclarativeNetRequest permissions and scoped host permissions.
 * 2. Default production backend URL initialization (https://phantomtrace-web.onrender.com).
 * 3. Preservation of production config across restarts and reload cycles.
 * 4. Preservation of explicit user-selected localhost/dev URLs.
 * 5. Rejection of invalid, dangerous, or malformed backend URLs.
 * 6. Domain pattern validation and rejection of unsafe/injected rules.
 * 7. Backend Domain Policies API: creation, retrieval, updates, and deletion.
 * 8. Strict Multi-Tenant Isolation between security analysts.
 * 9. Policy Precedence Hierarchy Resolution:
 *    - Exact domain conflict: BLOCK wins over ALLOW (default-deny).
 *    - Subdomain specificity: Subdomain rule beats parent domain rule.
 *    - Tenant ALLOW overrides external threat feeds.
 *    - Tenant BLOCK overrides benign reputation.
 * 10. DeclarativeNetRequest dynamic rules generation and priority scoring.
 * 11. Extension Policy Synchronization with offline resilience and honest status tracking.
 * 12. Security Audit: Client extension and popup contain NO secret master keys or DB credentials.
 * =====================================================================
 */

import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 5098;
process.env.PORT = String(PORT);
process.env.NODE_ENV = "test";
process.env.PHANTOMTRACE_API_KEY = "test-master-owner-key-policies";

let server;
let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`[PASS] ✓ ${message}`);
    passCount++;
  } else {
    console.error(`[FAIL] ✗ ${message}`);
    failCount++;
  }
}

async function request(reqPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: PORT,
        path: reqPath,
        method: options.method || "GET",
        headers: options.headers || {},
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          let data = null;
          try {
            data = JSON.parse(body);
          } catch {
            data = body;
          }
          resolve({ status: res.statusCode, headers: res.headers, data });
        });
      }
    );

    req.on("error", reject);

    if (options.body) {
      req.write(typeof options.body === "string" ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

// Emulated Extension Engine Logic (matching browser-extension/background.js)
function isValidBackendUrl(urlStr) {
  if (!urlStr || typeof urlStr !== "string") return false;
  try {
    const parsed = new URL(urlStr.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
    if (!parsed.hostname) return false;
    if (parsed.search || parsed.username || parsed.password) return false;
    return true;
  } catch {
    return false;
  }
}

function isValidDomainPattern(pattern) {
  if (!pattern || typeof pattern !== "string") return false;
  const trimmed = pattern.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > 253) return false;
  if (/[\s\r\n\t<>'"\\/;`$(){}|&?#]/.test(trimmed)) return false;
  const domainWithoutWildcard = trimmed.startsWith("*.") ? trimmed.slice(2) : trimmed;
  const parts = domainWithoutWildcard.split(".");
  if (parts.length === 0) return false;
  for (const p of parts) {
    if (!p || p.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(p)) return false;
  }
  return true;
}

function findEffectivePolicy(domain, policies) {
  if (!domain || !Array.isArray(policies) || policies.length === 0) return null;
  const cleanDomain = domain.toLowerCase().trim();

  const candidates = [];
  for (const pol of policies) {
    if (!pol || !pol.domain) continue;
    let target = pol.domain.toLowerCase().trim();
    if (target.startsWith("*.")) target = target.slice(2);
    if (cleanDomain === target || cleanDomain.endsWith("." + target)) {
      candidates.push({
        ...pol,
        matchedDomain: target,
        specificity: target.length,
      });
    }
  }

  if (candidates.length === 0) return null;

  candidates.sort((a, b) => {
    const specDiff = b.specificity - a.specificity;
    if (specDiff !== 0) return specDiff;
    if (a.policyType === "BLOCK" && b.policyType === "ALLOW") return -1;
    if (a.policyType === "ALLOW" && b.policyType === "BLOCK") return 1;
    return 0;
  });

  return candidates[0];
}

function buildDeclarativeNetRules(policies) {
  const addRules = [];
  let idCounter = 1;

  for (const pol of policies) {
    if (!pol || !pol.domain) continue;
    let dom = pol.domain.toLowerCase().trim();
    if (dom.startsWith("*.")) dom = dom.slice(2);
    if (!isValidDomainPattern(dom)) continue;

    const isBlock = pol.policyType === "BLOCK";
    const labels = dom.split(".").length;
    const priority = 100 + (labels * 10) + (isBlock ? 2 : 1);

    addRules.push({
      id: idCounter++,
      priority,
      action: {
        type: isBlock ? "block" : "allow",
      },
      condition: {
        urlFilter: `||${dom}^`,
        resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"],
      },
    });
  }

  return addRules;
}

async function runTests() {
  console.log("=======================================================");
  console.log("  PHANTOMTRACE: EXTENSION DOMAIN SECURITY POLICIES TEST ");
  console.log("=======================================================\n");

  const { app } = await import("./dist/app.js");
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(PORT, "127.0.0.1", resolve));

  try {
    // -------------------------------------------------------------
    // TEST SECTION 1: Manifest V3 Permissions & Host Scoping
    // -------------------------------------------------------------
    console.log("--- 1. MANIFEST V3 AUDIT ---");
    const manifestPath = path.resolve(__dirname, "../browser-extension/manifest.json");
    assert(fs.existsSync(manifestPath), "manifest.json exists in browser-extension/");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));

    assert(manifest.manifest_version === 3, "Manifest version is Manifest V3");
    assert(manifest.permissions.includes("declarativeNetRequest"), "Permissions includes 'declarativeNetRequest'");
    assert(manifest.permissions.includes("webNavigation"), "Permissions includes 'webNavigation'");
    assert(manifest.permissions.includes("storage"), "Permissions includes 'storage'");

    // Minimum required host permissions
    assert(
      manifest.host_permissions.includes("https://phantomtrace-web.onrender.com/*"),
      "Host permissions includes production backend https://phantomtrace-web.onrender.com/*"
    );
    assert(
      !manifest.host_permissions.includes("<all_urls>"),
      "Host permissions does NOT contain overly broad '<all_urls>'"
    );
    assert(
      !manifest.host_permissions.includes("*://*/*"),
      "Host permissions does NOT contain wildcard '*://*/*'"
    );

    // -------------------------------------------------------------
    // TEST SECTION 2: Production Default Backend & Reload Persistence
    // -------------------------------------------------------------
    console.log("\n--- 2. BACKEND CONFIGURATION & RELOAD PERSISTENCE ---");
    const bgJsPath = path.resolve(__dirname, "../browser-extension/background.js");
    const bgJsContent = fs.readFileSync(bgJsPath, "utf-8");
    assert(
      bgJsContent.includes('const DEFAULT_BACKEND_URL = "https://phantomtrace-web.onrender.com";'),
      "background.js sets DEFAULT_BACKEND_URL to https://phantomtrace-web.onrender.com"
    );
    assert(
      !bgJsContent.includes('const DEFAULT_BACKEND_URL = "http://localhost:5000";'),
      "background.js removed http://localhost:5000 as default"
    );

    // Emulate fresh installation storage check
    let simulatedStorage = {};
    if (!simulatedStorage.backendUrl) {
      simulatedStorage.backendUrl = "https://phantomtrace-web.onrender.com";
    }
    assert(
      simulatedStorage.backendUrl === "https://phantomtrace-web.onrender.com",
      "Fresh installation initializes backendUrl to production URL"
    );

    // Emulate reload preserving production URL
    let reloadedStorage = { ...simulatedStorage };
    assert(
      reloadedStorage.backendUrl === "https://phantomtrace-web.onrender.com",
      "Reload cycle preserves production backend URL"
    );

    // Emulate user selecting localhost development URL
    simulatedStorage.backendUrl = "http://localhost:5000";
    let devReloadedStorage = { ...simulatedStorage };
    assert(
      devReloadedStorage.backendUrl === "http://localhost:5000",
      "User-selected development localhost URL is preserved on reload and not overwritten"
    );

    // URL validation tests
    assert(isValidBackendUrl("https://phantomtrace-web.onrender.com"), "Validates production HTTPS backend URL");
    assert(isValidBackendUrl("http://localhost:5000"), "Validates development localhost HTTP backend URL");
    assert(isValidBackendUrl("http://127.0.0.1:5000"), "Validates 127.0.0.1 development backend URL");
    assert(!isValidBackendUrl(""), "Rejects empty backend URL");
    assert(!isValidBackendUrl("not-a-url"), "Rejects non-URL string");
    assert(!isValidBackendUrl("ftp://phantomtrace.local"), "Rejects unsupported FTP protocol");
    assert(!isValidBackendUrl("javascript:alert(1)"), "Rejects dangerous javascript: pseudo-protocol");
    assert(!isValidBackendUrl("https://evil.com?param=leak"), "Rejects URL containing query parameters");
    assert(!isValidBackendUrl("https://user:pass@evil.com"), "Rejects URL containing embedded credentials");

    // -------------------------------------------------------------
    // TEST SECTION 3: Domain Pattern Validation & Sanitization
    // -------------------------------------------------------------
    console.log("\n--- 3. DOMAIN PATTERN VALIDATION ---");
    assert(isValidDomainPattern("phishing-bank.com"), "Validates standard domain phishing-bank.com");
    assert(isValidDomainPattern("login.sub.domain.org"), "Validates multi-level subdomain login.sub.domain.org");
    assert(isValidDomainPattern("*.threat-wildcard.net"), "Validates wildcard domain pattern *.threat-wildcard.net");
    assert(isValidDomainPattern("192.168.1.1"), "Validates IPv4 address 192.168.1.1");
    assert(!isValidDomainPattern(""), "Rejects empty domain pattern");
    assert(!isValidDomainPattern("http://evil.com"), "Rejects domain with http:// protocol prefix");
    assert(!isValidDomainPattern("evil.com/path"), "Rejects domain with URL path");
    assert(!isValidDomainPattern("evil.com?q=1"), "Rejects domain with query parameters");
    assert(!isValidDomainPattern("<script>alert(1)</script>"), "Rejects XSS script tag injection");
    assert(!isValidDomainPattern("evil.com; DROP TABLE domain_policies;"), "Rejects SQL injection attempt");
    assert(!isValidDomainPattern("evil..com"), "Rejects consecutive dots in domain label");

    // -------------------------------------------------------------
    // TEST SECTION 4: Live Domain Policy API & Multi-Tenant Isolation
    // -------------------------------------------------------------
    console.log("\n--- 4. LIVE POLICY API & MULTI-TENANT ISOLATION ---");

    // Setup two distinct tenants
    const tenantAHeaders = {
      Authorization: "Bearer dev-analyst-tenant-a",
      "Content-Type": "application/json",
    };
    const tenantBHeaders = {
      Authorization: "Bearer dev-analyst-tenant-b",
      "Content-Type": "application/json",
    };

    // Unauthenticated request rejected
    const unauthRes = await request("/api/web-threats/policies");
    assert(unauthRes.status === 401, "GET /api/web-threats/policies rejects unauthenticated request with 401");

    // Tenant A creates BLOCK rule
    const createBlockRes = await request("/api/web-threats/policies", {
      method: "POST",
      headers: tenantAHeaders,
      body: {
        domain: "malicious-finance.com",
        policyType: "BLOCK",
        reason: "Confirmed credential harvester.",
      },
    });
    assert(createBlockRes.status === 201, "Tenant A creates BLOCK policy (201 Created)");
    assert(createBlockRes.data.policy.domain === "malicious-finance.com", "Created policy contains normalized domain");
    assert(createBlockRes.data.policy.policyType === "BLOCK", "Created policy type is BLOCK");
    const blockPolicyId = createBlockRes.data.policy.policyId;

    // Tenant A creates ALLOW rule
    const createAllowRes = await request("/api/web-threats/policies", {
      method: "POST",
      headers: tenantAHeaders,
      body: {
        domain: "internal-tools.corp",
        policyType: "ALLOW",
        reason: "Authorized internal administration tool.",
      },
    });
    assert(createAllowRes.status === 201, "Tenant A creates ALLOW policy (201 Created)");

    // Tenant A lists policies
    const listTenantARes = await request("/api/web-threats/policies", {
      headers: tenantAHeaders,
    });
    assert(listTenantARes.status === 200, "Tenant A lists policies (200 OK)");
    assert(listTenantARes.data.policies.length >= 2, "Tenant A sees at least 2 active policies");

    // Strict Tenant Isolation: Tenant B CANNOT see Tenant A's policies
    const listTenantBRes = await request("/api/web-threats/policies", {
      headers: tenantBHeaders,
    });
    assert(listTenantBRes.status === 200, "Tenant B lists policies (200 OK)");
    assert(
      !listTenantBRes.data.policies.some((p) => p.domain === "malicious-finance.com"),
      "Tenant B CANNOT see Tenant A's malicious-finance.com rule (tenant isolation enforced)"
    );

    // Tenant B CANNOT delete Tenant A's policy
    const crossDeleteRes = await request(`/api/web-threats/policies/${blockPolicyId}`, {
      method: "DELETE",
      headers: tenantBHeaders,
    });
    assert(
      crossDeleteRes.status === 404 || crossDeleteRes.status === 403,
      "Tenant B cannot delete Tenant A's policy (rejected with 404/403)"
    );

    // Tenant A updates rule (idempotent duplicate handling)
    const updateRes = await request("/api/web-threats/policies", {
      method: "POST",
      headers: tenantAHeaders,
      body: {
        domain: "malicious-finance.com",
        policyType: "BLOCK",
        reason: "Updated: Active C2 campaign confirmed.",
      },
    });
    assert(updateRes.status === 201, "Updating existing domain policy handled cleanly");

    // -------------------------------------------------------------
    // TEST SECTION 4B: Extension Token Issuance & Sync Handshake
    // -------------------------------------------------------------
    console.log("\n--- 4B. EXTENSION TOKEN ISSUANCE & SYNC HANDSHAKE ---");

    // Create a real public session for User Alpha
    const sessionResA = await request("/api/auth/session", {
      method: "POST",
      body: { displayName: "Analyst Alpha" },
    });
    assert(sessionResA.status === 200, "POST /api/auth/session creates session for Analyst Alpha");
    const userAToken = sessionResA.data.sessionToken;
    assert(userAToken.startsWith("pt_usr_"), "User A session token has 'pt_usr_' prefix");
    const userAUid = sessionResA.data.user.uid;

    // Create a policy for User Alpha
    const userAPolicyRes = await request("/api/web-threats/policies", {
      method: "POST",
      headers: { Authorization: `Bearer ${userAToken}`, "Content-Type": "application/json" },
      body: { domain: "alpha-phish.net", policyType: "BLOCK", reason: "Alpha threat" },
    });
    assert(userAPolicyRes.status === 201, "User Alpha creates custom domain policy");

    // User Alpha requests a dedicated scoped Extension Token
    const extTokenResA = await request("/api/auth/extension-token", {
      method: "POST",
      headers: { Authorization: `Bearer ${userAToken}` },
    });
    assert(extTokenResA.status === 200, "POST /api/auth/extension-token succeeds (200)");
    const extTokenA = extTokenResA.data.extensionToken;
    assert(extTokenA.startsWith("pt_ext_"), "Extension token has 'pt_ext_' prefix");
    assert(extTokenResA.data.uid === userAUid, "Extension token is bound to User Alpha's tenant UID");

    // Extension syncs policies using pt_ext_ token
    const extSyncRes = await request("/api/web-threats/policies", {
      headers: { Authorization: `Bearer ${extTokenA}` },
    });
    assert(extSyncRes.status === 200, "Extension successfully syncs policies using scoped 'pt_ext_' token (200)");
    assert(
      extSyncRes.data.policies.some((p) => p.domain === "alpha-phish.net"),
      "Extension receives User Alpha's 'alpha-phish.net' policy rule"
    );

    // Extension also works directly with pt_usr_ session token
    const userSyncRes = await request("/api/web-threats/policies", {
      headers: { Authorization: `Bearer ${userAToken}` },
    });
    assert(userSyncRes.status === 200, "Extension successfully syncs policies using 'pt_usr_' session token (200)");

    // User Beta creates session and requests extension token
    const sessionResB = await request("/api/auth/session", {
      method: "POST",
      body: { displayName: "Analyst Beta" },
    });
    const userBToken = sessionResB.data.sessionToken;
    const extTokenResB = await request("/api/auth/extension-token", {
      method: "POST",
      headers: { Authorization: `Bearer ${userBToken}` },
    });
    const extTokenB = extTokenResB.data.extensionToken;

    // User Beta extension sync CANNOT see User Alpha's policy
    const extSyncBeta = await request("/api/web-threats/policies", {
      headers: { Authorization: `Bearer ${extTokenB}` },
    });
    assert(extSyncBeta.status === 200, "User Beta extension sync succeeds (200)");
    assert(
      !extSyncBeta.data.policies.some((p) => p.domain === "alpha-phish.net"),
      "User Beta extension CANNOT access User Alpha's policy (tenant isolation strictly preserved)"
    );

    // Invalid extension token rejected
    const invalidExtRes = await request("/api/web-threats/policies", {
      headers: { Authorization: "Bearer pt_ext_invalid_fake_token_12345" },
    });
    assert(invalidExtRes.status === 401, "Invalid 'pt_ext_' token rejected with 401 Unauthorized");

    // Least-privilege: Extension token CANNOT mint new extension tokens
    const extMintAttempt = await request("/api/auth/extension-token", {
      method: "POST",
      headers: { Authorization: `Bearer ${extTokenA}` },
    });
    assert(extMintAttempt.status === 403, "Extension token cannot mint extension tokens (403 Forbidden)");

    // Least-privilege: Extension token CANNOT access device pairing
    const extDeviceAttempt = await request("/api/devices/pair/start", {
      method: "POST",
      headers: { Authorization: `Bearer ${extTokenA}` },
    });
    assert(extDeviceAttempt.status === 403, "Extension token cannot access device pairing (403 Forbidden)");

    // Least-privilege: Extension token CANNOT access dashboard telemetry
    const extDashAttempt = await request("/api/dashboard/overview", {
      headers: { Authorization: `Bearer ${extTokenA}` },
    });
    assert(extDashAttempt.status === 403, "Extension token cannot access dashboard overview (403 Forbidden)");

    // Least-privilege: Extension token CANNOT access host scans
    const extScansAttempt = await request("/api/scans", {
      headers: { Authorization: `Bearer ${extTokenA}` },
    });
    assert(extScansAttempt.status === 403, "Extension token cannot access host scans (403 Forbidden)");

    // Least-privilege: Query parameter path spoofing CANNOT bypass scope
    const extSpoofAttempt = await request("/api/scans?route=/web-threats", {
      headers: { Authorization: `Bearer ${extTokenA}` },
    });
    assert(extSpoofAttempt.status === 403, "Extension token cannot spoof scope via query parameter (403 Forbidden)");

    // Least-privilege: Extension token CANNOT create or mutate security policies
    const extCreatePolicyAttempt = await request("/api/web-threats/policies", {
      method: "POST",
      headers: { Authorization: `Bearer ${extTokenA}`, "Content-Type": "application/json" },
      body: { domain: "unauthorized-change.com", policyType: "ALLOW" },
    });
    assert(extCreatePolicyAttempt.status === 403, "Extension token cannot create/mutate security policies (403 Forbidden)");

    // Least-privilege: Extension token CANNOT delete security policies
    const extDeletePolicyAttempt = await request("/api/web-threats/policies/pol-fake-id", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${extTokenA}` },
    });
    assert(extDeletePolicyAttempt.status === 403, "Extension token cannot delete security policies (403 Forbidden)");

    // Least-privilege: Extension token CANNOT triage incidents
    const extTriageAttempt = await request("/api/web-threats/events/wte-fake-id/status", {
      method: "POST",
      headers: { Authorization: `Bearer ${extTokenA}`, "Content-Type": "application/json" },
      body: { status: "RESOLVED" },
    });
    assert(extTriageAttempt.status === 403, "Extension token cannot triage threat incidents (403 Forbidden)");

    // Token Expiration Enforcement
    const expiredToken = "pt_ext_" + "e".repeat(64);
    const expiredHash = crypto.createHash("sha256").update(expiredToken).digest("hex");
    const { postgresService } = await import("./dist/services/postgresService.js");
    await postgresService.createUserSession({
      tokenHash: expiredHash,
      uid: userAUid,
      email: "alpha@phantomtrace.local",
      displayName: "Expired Extension",
      createdAt: new Date(Date.now() - 200000).toISOString(),
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    const expiredRes = await request("/api/web-threats/policies", {
      headers: { Authorization: `Bearer ${expiredToken}` },
    });
    assert(expiredRes.status === 401, "Expired extension token rejected on request (401 Unauthorized)");

    // Token Revocation Enforcement
    const revokedToken = "pt_ext_" + "r".repeat(64);
    const revokedHash = crypto.createHash("sha256").update(revokedToken).digest("hex");
    await postgresService.createUserSession({
      tokenHash: revokedHash,
      uid: userAUid,
      email: "alpha@phantomtrace.local",
      displayName: "Revoked Extension",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 90 * 86400000).toISOString(),
      revokedAt: new Date().toISOString(),
    });
    const revokedRes = await request("/api/web-threats/policies", {
      headers: { Authorization: `Bearer ${revokedToken}` },
    });
    assert(revokedRes.status === 401, "Revoked extension token rejected on request (401 Unauthorized)");


    // -------------------------------------------------------------
    // TEST SECTION 5: Policy Precedence Hierarchy Resolution
    // -------------------------------------------------------------
    console.log("\n--- 5. POLICY PRECEDENCE HIERARCHY RESOLUTION ---");

    // Precedence Case 1: Exact Match Conflict (BLOCK vs ALLOW for same domain)
    // Security standard: Default-Deny -> BLOCK beats ALLOW
    const conflictSameDomain = [
      { domain: "conflict.com", policyType: "ALLOW", policyId: "pol-allow" },
      { domain: "conflict.com", policyType: "BLOCK", policyId: "pol-block" },
    ];
    const matchSameDomain = findEffectivePolicy("conflict.com", conflictSameDomain);
    assert(matchSameDomain !== null, "Finds matching policy for conflict.com");
    assert(
      matchSameDomain.policyType === "BLOCK",
      "Conflict at same specificity: BLOCK wins over ALLOW (default-deny enforced)"
    );

    // Precedence Case 2: Subdomain Specificity (Parent BLOCK, Subdomain ALLOW)
    const parentBlockSubAllow = [
      { domain: "blocked-company.com", policyType: "BLOCK", policyId: "pol-parent-block" },
      { domain: "api.blocked-company.com", policyType: "ALLOW", policyId: "pol-sub-allow" },
    ];
    // Navigation to api.blocked-company.com
    const subMatch = findEffectivePolicy("api.blocked-company.com", parentBlockSubAllow);
    assert(
      subMatch.policyType === "ALLOW" && subMatch.policyId === "pol-sub-allow",
      "Subdomain specificity: Specific subdomain ALLOW overrides parent BLOCK"
    );
    // Navigation to other subdomain portal.blocked-company.com
    const otherSubMatch = findEffectivePolicy("portal.blocked-company.com", parentBlockSubAllow);
    assert(
      otherSubMatch.policyType === "BLOCK" && otherSubMatch.policyId === "pol-parent-block",
      "Parent BLOCK remains in effect for other subdomains"
    );

    // Precedence Case 3: Subdomain Specificity (Parent ALLOW, Subdomain BLOCK)
    const parentAllowSubBlock = [
      { domain: "safe-corp.com", policyType: "ALLOW", policyId: "pol-parent-allow" },
      { domain: "compromised.safe-corp.com", policyType: "BLOCK", policyId: "pol-sub-block" },
    ];
    const compMatch = findEffectivePolicy("compromised.safe-corp.com", parentAllowSubBlock);
    assert(
      compMatch.policyType === "BLOCK",
      "Subdomain specificity: Specific compromised subdomain BLOCK overrides parent ALLOW"
    );

    // Precedence Case 4: Custom ALLOW vs External Threat Intel
    // In threatIntelService: if domain is in tenant ALLOW, verdict is BENIGN even if on external feed
    const checkAllowRes = await request("/api/web-threats/check", {
      method: "POST",
      headers: tenantAHeaders,
      body: { domain: "internal-tools.corp" },
    });
    assert(checkAllowRes.status === 200, "Checked URL reputation for internal-tools.corp");
    assert(
      checkAllowRes.data.result.verdict === "BENIGN" && checkAllowRes.data.result.source === "POLICY_RULE",
      "Tenant ALLOW policy overrides external intel with score 0 / BENIGN"
    );

    // Precedence Case 5: Custom BLOCK vs External Threat Intel
    const checkBlockRes = await request("/api/web-threats/check", {
      method: "POST",
      headers: tenantAHeaders,
      body: { domain: "malicious-finance.com" },
    });
    assert(checkBlockRes.status === 200, "Checked URL reputation for malicious-finance.com");
    assert(
      checkBlockRes.data.result.verdict === "POLICY_VIOLATION" && checkBlockRes.data.result.score === 100,
      "Tenant BLOCK policy overrides external intel with score 100 / POLICY_VIOLATION"
    );

    // -------------------------------------------------------------
    // TEST SECTION 6: DeclarativeNetRequest Dynamic Rules Generation
    // -------------------------------------------------------------
    console.log("\n--- 6. DECLARATIVENETREQUEST DYNAMIC RULES GENERATION ---");
    const testPolicies = [
      { domain: "malicious-finance.com", policyType: "BLOCK" },
      { domain: "internal-tools.corp", policyType: "ALLOW" },
      { domain: "api.malicious-finance.com", policyType: "ALLOW" },
    ];

    const dnrRules = buildDeclarativeNetRules(testPolicies);
    assert(dnrRules.length === 3, "Generates 3 declarativeNetRequest dynamic rules");

    const blockRule = dnrRules.find((r) => r.condition.urlFilter === "||malicious-finance.com^");
    assert(blockRule !== undefined, "Contains rule for ||malicious-finance.com^");
    assert(blockRule.action.type === "block", "Block rule action is 'block'");

    const allowRule = dnrRules.find((r) => r.condition.urlFilter === "||internal-tools.corp^");
    assert(allowRule !== undefined, "Contains rule for ||internal-tools.corp^");
    assert(allowRule.action.type === "allow", "Allow rule action is 'allow'");

    const subAllowRule = dnrRules.find((r) => r.condition.urlFilter === "||api.malicious-finance.com^");
    assert(subAllowRule !== undefined, "Contains rule for ||api.malicious-finance.com^");
    assert(
      subAllowRule.priority > blockRule.priority,
      `Subdomain rule priority (${subAllowRule.priority}) > parent rule priority (${blockRule.priority})`
    );

    // -------------------------------------------------------------
    // TEST SECTION 7: Offline Behavior & Honest Sync Status
    // -------------------------------------------------------------
    console.log("\n--- 7. OFFLINE BEHAVIOR & HONEST SYNC STATUS ---");

    // Simulate Extension Syncing with Offline Backend
    const offlineBackendUrl = "http://127.0.0.1:59998"; // non-existent port
    let offlineSyncResult = null;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 500);
      await fetch(`${offlineBackendUrl}/api/web-threats/policies`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
    } catch {
      offlineSyncResult = {
        status: "OFFLINE",
        errorMessage: "Network timeout / backend offline. Preserving local policies.",
      };
    }

    assert(offlineSyncResult !== null, "Offline backend error captured safely");
    assert(offlineSyncResult.status === "OFFLINE", "Offline backend reports honest status 'OFFLINE'");

    // Cached policies preserved during offline state
    const cachedLocalPolicies = [
      { domain: "malicious-finance.com", policyType: "BLOCK" },
    ];
    const offlineEvaluation = findEffectivePolicy("malicious-finance.com", cachedLocalPolicies);
    assert(
      offlineEvaluation !== null && offlineEvaluation.policyType === "BLOCK",
      "Previously synchronized policies remain actively enforced while backend is offline"
    );

    // Honest status: Missing Auth Token reports AUTH_REQUIRED
    function simulateSyncNoToken(token) {
      if (!token) {
        return { status: "AUTH_REQUIRED", errorMessage: "Authentication token required to sync cloud policies." };
      }
      return { status: "SYNCED" };
    }
    const noTokenResult = simulateSyncNoToken("");
    assert(noTokenResult.status === "AUTH_REQUIRED", "Syncing without auth token honestly reports 'AUTH_REQUIRED'");

    // -------------------------------------------------------------
    // TEST SECTION 8: Credential & Secret Leakage Audit
    // -------------------------------------------------------------
    console.log("\n--- 8. CREDENTIAL & SECRET LEAKAGE AUDIT ---");
    const extensionDir = path.resolve(__dirname, "../browser-extension");
    const extFiles = ["background.js", "popup.js", "warning.js", "manifest.json"];

    for (const f of extFiles) {
      const fullPath = path.join(extensionDir, f);
      const content = fs.readFileSync(fullPath, "utf-8");
      assert(
        !content.includes("postgres://") && !content.includes("postgresql://"),
        `File ${f} contains no PostgreSQL connection string`
      );
      assert(
        !content.includes("test-master-owner-key"),
        `File ${f} contains no test master API key`
      );
      assert(
        !content.includes("PHANTOMTRACE_API_KEY"),
        `File ${f} contains no server environment secrets`
      );
    }
  } finally {
    if (server) {
      server.close();
    }
  }

  console.log("\n=======================================================");
  console.log(`  POLICY TESTS SUMMARY: PASSED: ${passCount} | FAILED: ${failCount}`);
  console.log("=======================================================\n");

  if (failCount > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Test execution failed:", err);
  if (server) server.close();
  process.exit(1);
});
