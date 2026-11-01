/**
 * =====================================================================
 * PHANTOMTRACE WEB THREAT MONITOR — BACKGROUND SERVICE WORKER (V3)
 * =====================================================================
 * Privacy & Security Guarantees:
 * 1. Checks ONLY domain/hostname. Never sends queries, passwords, or cookies.
 * 2. Conservative evaluation: Unknown domains are never marked malicious.
 * 3. Fail-safe: Timeouts or offline backend allow navigation without blocking.
 * 4. Deduplication: Prevents alert loops and respects user dismissals.
 * 5. Production Default: Uses https://phantomtrace-web.onrender.com by default.
 * 6. Policy Enforcement: Enforces Domain Security Policies via declarativeNetRequest
 *    and onBeforeNavigate with deterministic precedence:
 *    Subdomain Specificity > Custom BLOCK (Default Deny) > Custom ALLOW > External Intel.
 * =====================================================================
 */

const DEFAULT_BACKEND_URL = "https://phantomtrace-web.onrender.com";
const LOCAL_AGENT_URL = "http://127.0.0.1:49152";

/**
 * Validates backend URL format safely.
 */
function isValidBackendUrl(urlStr) {
  if (!urlStr || typeof urlStr !== "string") return false;
  try {
    const parsed = new URL(urlStr.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
    if (!parsed.hostname) return false;
    // Disallow query params or user credentials in backend URL
    if (parsed.search || parsed.username || parsed.password) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates domain pattern to prevent injection or invalid rules.
 */
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

// In-memory runtime state
const runtimeState = {
  monitoringEnabled: false, // Explicit enablement required
  backendUrl: DEFAULT_BACKEND_URL,
  localAgentEnabled: true,
  backendConnected: false,
  dismissedDomains: new Set(),
  reputationCache: new Map(), // domain -> { result, expiresAt }
  recentEvents: [],
  domainPolicies: [], // Synced custom domain policies
  policySyncMeta: {
    status: "IDLE", // IDLE, SYNCED, OFFLINE, AUTH_REQUIRED, AUTH_ERROR
    lastSyncTime: null,
    blockCount: 0,
    allowCount: 0,
    errorMessage: null,
  },
};

// Initialize settings from storage
chrome.storage.local.get(
  ["monitoringEnabled", "backendUrl", "localAgentEnabled", "domainPolicies", "policySyncMeta"],
  (stored) => {
    if (typeof stored.monitoringEnabled === "boolean") {
      runtimeState.monitoringEnabled = stored.monitoringEnabled;
    } else {
      runtimeState.monitoringEnabled = false;
      chrome.storage.local.set({ monitoringEnabled: false });
    }

    // Preserve saved backend URL if valid; if missing or invalid, initialize with production default
    if (stored.backendUrl && isValidBackendUrl(stored.backendUrl)) {
      runtimeState.backendUrl = stored.backendUrl.replace(/\/+$/, "");
    } else {
      runtimeState.backendUrl = DEFAULT_BACKEND_URL;
      chrome.storage.local.set({ backendUrl: DEFAULT_BACKEND_URL });
    }

    if (typeof stored.localAgentEnabled === "boolean") {
      runtimeState.localAgentEnabled = stored.localAgentEnabled;
    }

    // Load cached policies
    if (Array.isArray(stored.domainPolicies)) {
      runtimeState.domainPolicies = stored.domainPolicies;
    }

    if (stored.policySyncMeta && typeof stored.policySyncMeta === "object") {
      runtimeState.policySyncMeta = stored.policySyncMeta;
    }

    updateBadge();
    checkBackendHealth();
    void syncDomainPolicies();
  }
);

// Fresh installation initialization
chrome.runtime.onInstalled.addListener((_details) => {
  chrome.storage.local.get(["backendUrl", "monitoringEnabled", "localAgentEnabled"], (stored) => {
    const updates = {};
    if (!stored.backendUrl || !isValidBackendUrl(stored.backendUrl)) {
      updates.backendUrl = DEFAULT_BACKEND_URL;
    }
    if (typeof stored.monitoringEnabled !== "boolean") {
      updates.monitoringEnabled = false;
    }
    if (typeof stored.localAgentEnabled !== "boolean") {
      updates.localAgentEnabled = true;
    }
    if (Object.keys(updates).length > 0) {
      chrome.storage.local.set(updates);
    }
  });
});

// Listen for storage changes
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.monitoringEnabled) {
    runtimeState.monitoringEnabled = changes.monitoringEnabled.newValue;
    updateBadge();
  }
  if (changes.backendUrl) {
    const newUrl = changes.backendUrl.newValue;
    if (isValidBackendUrl(newUrl)) {
      runtimeState.backendUrl = newUrl.replace(/\/+$/, "");
    } else {
      runtimeState.backendUrl = DEFAULT_BACKEND_URL;
    }
    checkBackendHealth();
    void syncDomainPolicies();
  }
  if (changes.localAgentEnabled) {
    runtimeState.localAgentEnabled = changes.localAgentEnabled.newValue;
  }
  if (changes.authToken) {
    checkBackendHealth();
    void syncDomainPolicies();
  }
});

function updateBadge() {
  if (!runtimeState.monitoringEnabled) {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
  } else if (!runtimeState.backendConnected) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
  } else {
    chrome.action.setBadgeText({ text: "ON" });
    chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
  }
}

async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${runtimeState.backendUrl}/api/web-threats/status`, {
      signal: controller.signal,
    });
    clearTimeout(timer);
    runtimeState.backendConnected = res.ok;
    if (res.ok) {
      void drainPendingEventsQueue();
    }
  } catch {
    runtimeState.backendConnected = false;
  }
  updateBadge();
}

// Periodically check backend health every 60 seconds
setInterval(checkBackendHealth, 60000);

// Periodically re-sync domain policies every 5 minutes
setInterval(() => {
  if (runtimeState.backendConnected) {
    void syncDomainPolicies();
  }
}, 300000);

/**
 * Normalizes hostname safely. Strips query parameters, auth info, and ports.
 */
function extractSafeDomain(urlStr) {
  try {
    const url = new URL(urlStr);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    let hostname = url.hostname.toLowerCase();
    if (hostname.endsWith(".")) hostname = hostname.slice(0, -1);
    return hostname;
  } catch {
    return null;
  }
}

/**
 * Resolves conflicting policies using explicit, documented precedence:
 * 1. Subdomain Specificity: More specific subdomain rule takes precedence over parent domain.
 * 2. Tie-breaker at same specificity: BLOCK takes precedence over ALLOW (default-deny).
 * 3. Tenant ALLOW overrides external threat feeds.
 */
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
    // Same specificity: BLOCK takes precedence over ALLOW
    if (a.policyType === "BLOCK" && b.policyType === "ALLOW") return -1;
    if (a.policyType === "ALLOW" && b.policyType === "BLOCK") return 1;
    return 0;
  });

  return candidates[0];
}

/**
 * Applies active domain policies to Chrome/Edge declarativeNetRequest dynamic rules.
 */
async function applyDeclarativeNetRules(policies) {
  if (
    typeof chrome === "undefined" ||
    !chrome.declarativeNetRequest ||
    !chrome.declarativeNetRequest.updateDynamicRules
  ) {
    return;
  }

  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing.map((r) => r.id);

    const addRules = [];
    let idCounter = 1;

    for (const pol of policies) {
      if (!pol || !pol.domain) continue;
      let dom = pol.domain.toLowerCase().trim();
      if (dom.startsWith("*.")) dom = dom.slice(2);
      if (!isValidDomainPattern(dom)) continue;

      const isBlock = pol.policyType === "BLOCK";
      const labels = dom.split(".").length;
      // Priority: Specificity (labels * 10) + (isBlock ? 2 : 1)
      const priority = 100 + (labels * 10) + (isBlock ? 2 : 1);

      addRules.push({
        id: idCounter++,
        priority,
        action: {
          type: isBlock ? "block" : "allow",
        },
        condition: {
          urlFilter: `||${dom}^`,
          resourceTypes: [
            "main_frame",
            "sub_frame",
            "stylesheet",
            "script",
            "image",
            "font",
            "object",
            "xmlhttprequest",
            "ping",
            "csp_report",
            "media",
            "websocket",
            "other",
          ],
        },
      });
    }

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules,
    });
  } catch (err) {
    console.warn("[declarativeNetRequest] Could not update dynamic rules:", err);
  }
}

/**
 * Synchronizes domain security policies from the backend API.
 */
async function syncDomainPolicies() {
  const token = await getAuthToken();
  if (!token) {
    runtimeState.policySyncMeta = {
      ...runtimeState.policySyncMeta,
      status: "AUTH_REQUIRED",
      errorMessage: "Authentication token required to sync cloud policies.",
    };
    return { success: false, status: "AUTH_REQUIRED" };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);

    const res = await fetch(`${runtimeState.backendUrl}/api/web-threats/policies`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (res.status === 401 || res.status === 403) {
      runtimeState.backendConnected = true;
      runtimeState.policySyncMeta = {
        ...runtimeState.policySyncMeta,
        status: "AUTH_ERROR",
        errorMessage: "Token rejected by backend (401/403).",
      };
      updateBadge();
      return { success: false, status: "AUTH_ERROR" };
    }

    if (!res.ok) {
      runtimeState.policySyncMeta = {
        ...runtimeState.policySyncMeta,
        status: "OFFLINE",
        errorMessage: `Backend server error (${res.status}). Preserving local policies.`,
      };
      return { success: false, status: "OFFLINE" };
    }

    const data = await res.json();
    const rawPolicies = Array.isArray(data.policies) ? data.policies : [];

    // Validate and sanitize rules
    const validPolicies = rawPolicies.filter((p) => {
      return (
        p &&
        typeof p.domain === "string" &&
        isValidDomainPattern(p.domain) &&
        (p.policyType === "BLOCK" || p.policyType === "ALLOW")
      );
    });

    const blockCount = validPolicies.filter((p) => p.policyType === "BLOCK").length;
    const allowCount = validPolicies.filter((p) => p.policyType === "ALLOW").length;
    const nowIso = new Date().toISOString();

    runtimeState.backendConnected = true;
    runtimeState.domainPolicies = validPolicies;
    runtimeState.policySyncMeta = {
      status: "SYNCED",
      lastSyncTime: nowIso,
      blockCount,
      allowCount,
      errorMessage: null,
    };
    updateBadge();

    // Persist to local storage
    chrome.storage.local.set({
      domainPolicies: validPolicies,
      policySyncMeta: runtimeState.policySyncMeta,
    });

    // Apply declarativeNetRequest dynamic rules
    await applyDeclarativeNetRules(validPolicies);

    return { success: true, status: "SYNCED", policiesCount: validPolicies.length };
  } catch {
    // Network offline or timeout: preserve previously stored local policies safely
    runtimeState.policySyncMeta = {
      ...runtimeState.policySyncMeta,
      status: "OFFLINE",
      errorMessage: "Backend offline / timeout. Preserving local policies.",
    };
    return { success: false, status: "OFFLINE" };
  }
}

/**
 * Navigation Monitor Listener
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only monitor top-level document navigations
  if (details.frameId !== 0) return;

  // If monitoring is disabled by the user, allow navigation without inspection
  if (!runtimeState.monitoringEnabled) return;

  // Don't monitor internal extension warning pages
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;

  const domain = extractSafeDomain(details.url);
  if (!domain) return;

  // Allow localhost / loopback addresses
  if (domain === "localhost" || domain === "127.0.0.1" || domain === "::1") return;

  // Check if domain was previously dismissed by user during this session
  if (runtimeState.dismissedDomains.has(domain)) return;

  // 1. Check Custom Domain Security Policies (Precedence: Explicit Policy > External Intel)
  const effectivePolicy = findEffectivePolicy(domain, runtimeState.domainPolicies);
  if (effectivePolicy) {
    if (effectivePolicy.policyType === "ALLOW") {
      // Explicit ALLOW policy overrides all external feeds -> Allow navigation immediately!
      return;
    } else if (effectivePolicy.policyType === "BLOCK") {
      // Explicit BLOCK policy -> Intercept immediately!
      const policyResult = {
        domain,
        verdict: "POLICY_VIOLATION",
        severity: "CRITICAL",
        score: 100,
        confidence: "HIGH",
        source: "POLICY_RULE",
        ruleId: effectivePolicy.policyId || "POLICY_USER_BLOCKED",
        explanation: effectivePolicy.reason || "Domain explicitly blocked by SOC security policy.",
      };
      handleVerdict(policyResult, details);
      return;
    }
  }

  // 2. Check in-memory reputation cache
  const cached = runtimeState.reputationCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    handleVerdict(cached.result, details);
    return;
  }

  // 3. Query Backend Reputation Check API
  try {
    const controller = new AbortController();
    const timeoutTimer = setTimeout(() => controller.abort(), 2500);

    const token = await getAuthToken();
    const headers = { "Content-Type": "application/json" };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch(`${runtimeState.backendUrl}/api/web-threats/check`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domain }),
      signal: controller.signal,
    });
    clearTimeout(timeoutTimer);

    if (!res.ok) {
      // Backend error -> fail safely, do not block user
      return;
    }

    const data = await res.json();
    const result = data.result;
    if (!result) return;

    // Cache result (10 minutes for benign/threats, 1 minute for unknown/errors)
    const ttl =
      result.verdict === "BENIGN" || result.severity === "HIGH" || result.severity === "CRITICAL"
        ? 10 * 60 * 1000
        : 60 * 1000;

    runtimeState.reputationCache.set(domain, {
      result,
      expiresAt: Date.now() + ttl,
    });

    handleVerdict(result, details);
  } catch {
    // Timeout or network offline -> fail safely, do not block navigation
    runtimeState.backendConnected = false;
    updateBadge();
  }
});

/**
 * Handles threat evaluation results and redirects to warning if needed.
 */
function handleVerdict(result, details) {
  const domain = result.domain;

  // Benign or Unknown: allow navigation
  if (result.verdict === "BENIGN" || result.verdict === "UNKNOWN") {
    return;
  }

  // Active Threat (Phishing, Malware, Unwanted Software, Suspicious Heuristic, or Policy Violation)
  const isThreat =
    result.verdict === "PHISHING" ||
    result.verdict === "MALWARE" ||
    result.verdict === "UNWANTED_SOFTWARE" ||
    result.verdict === "SUSPICIOUS_HEURISTIC" ||
    result.verdict === "POLICY_VIOLATION";

  if (!isThreat) return;

  // Record into recent extension events
  const eventRecord = {
    id: `ext-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    domain,
    targetUrl: details.url,
    verdict: result.verdict,
    severity: result.severity,
    score: result.score,
    source: result.source,
    ruleId: result.ruleId || "N/A",
    explanation: result.explanation,
    timestamp: new Date().toISOString(),
  };

  runtimeState.recentEvents.unshift(eventRecord);
  if (runtimeState.recentEvents.length > 50) {
    runtimeState.recentEvents.pop();
  }

  // Intercept navigation by redirecting to safe warning interstitial
  const warningUrl =
    chrome.runtime.getURL("warning.html") +
    `?domain=${encodeURIComponent(domain)}` +
    `&target=${encodeURIComponent(details.url)}` +
    `&severity=${encodeURIComponent(result.severity)}` +
    `&verdict=${encodeURIComponent(result.verdict)}` +
    `&score=${encodeURIComponent(result.score)}` +
    `&source=${encodeURIComponent(result.source)}` +
    `&ruleId=${encodeURIComponent(result.ruleId || "")}` +
    `&explanation=${encodeURIComponent(result.explanation)}`;

  chrome.tabs.update(details.tabId, { url: warningUrl });

  // Optional Windows Agent notification for High/Critical threats
  if (runtimeState.localAgentEnabled && (result.severity === "HIGH" || result.severity === "CRITICAL")) {
    dispatchLocalAgentNotification(result);
  }

  // Sync event to cloud backend if authenticated token is present or via guest ingestion
  syncEventToBackend(result, details.url);
}

/**
 * Dispatches high-confidence threat to local Windows Agent on 127.0.0.1:49152
 */
async function dispatchLocalAgentNotification(result) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1200);

    await fetch(`${LOCAL_AGENT_URL}/api/threats/browser-event`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        domain: result.domain,
        level: result.severity,
        score: result.score,
        classification: result.verdict,
        ruleId: result.ruleId,
        explanation: result.explanation,
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
  } catch {
    // Local agent offline: ignore safely
  }
}

/**
 * Sanitizes URLs before reporting:
 * - Completely strips credentials (username / password)
 * - Completely strips query parameters
 * - Completely strips hash fragments
 * Never transmits passwords, session cookies, form inputs, or sensitive query strings.
 */
function sanitizeUrlForReporting(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return "";
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString().slice(0, 500);
  } catch {
    return "";
  }
}

/**
 * Generates deterministic, stable Event ID to guarantee server-side idempotency
 * and prevent duplicate alert creation across retries.
 */
function generateStableEventId(domain, classification) {
  const timeBucket = Math.floor(Date.now() / 60000); // 1-minute bucket
  const cleanDomain = (domain || "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 16);
  const cleanClass = (classification || "threat").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 8);
  return `wte-ext-${cleanDomain}-${cleanClass}-${timeBucket}`;
}

const MAX_OFFLINE_QUEUE_SIZE = 50;
let isDrainingQueue = false;

/**
 * Transmits a single web threat event to the backend API.
 * Returns { success: boolean, permanentError: boolean }.
 */
async function transmitThreatEvent(eventPayload, token) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    const res = await fetch(`${runtimeState.backendUrl}/api/web-threats/events`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify(eventPayload),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (res.status === 200 || res.status === 201) {
      return { success: true, permanentError: false };
    }

    // Permanent client errors (400, 401, 403, 404): DO NOT keep retrying
    if (res.status === 400 || res.status === 401 || res.status === 403 || res.status === 404) {
      return { success: false, permanentError: true };
    }

    // Server error (5xx)
    return { success: false, permanentError: false };
  } catch {
    // Network offline or timeout
    return { success: false, permanentError: false };
  }
}

/**
 * Syncs security event to backend REST API with offline queuing and retry backoff.
 */
async function syncEventToBackend(result, rawUrl) {
  const sanitizedUrl = sanitizeUrlForReporting(rawUrl) || `https://${result.domain}`;
  const eventPayload = {
    id: generateStableEventId(result.domain, result.verdict),
    domain: (result.domain || "").slice(0, 255),
    url: sanitizedUrl,
    classification: result.verdict,
    severity: result.severity,
    score: typeof result.score === "number" ? result.score : 50,
    confidence: result.confidence || "MEDIUM",
    detectionSource: result.source || "THREAT_INTEL",
    ruleId: (result.ruleId || "N/A").slice(0, 80),
    explanation: (result.explanation || "Web threat detected.").slice(0, 500),
    browser: "Chrome/Edge Manifest V3",
    timestamp: new Date().toISOString(),
    attempts: 0,
  };

  const token = await getAuthToken();
  if (!token) {
    await enqueuePendingEvent(eventPayload);
    return;
  }

  const { success, permanentError } = await transmitThreatEvent(eventPayload, token);
  if (success) {
    return;
  }

  if (!permanentError) {
    await enqueuePendingEvent(eventPayload);
  }
}

/**
 * Saves event into chrome.storage.local offline queue.
 */
function enqueuePendingEvent(event) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["pendingThreatEvents"], (data) => {
      let queue = Array.isArray(data.pendingThreatEvents) ? data.pendingThreatEvents : [];
      queue = queue.filter((item) => item.id !== event.id);
      queue.push(event);
      if (queue.length > MAX_OFFLINE_QUEUE_SIZE) {
        queue.shift();
      }
      chrome.storage.local.set({ pendingThreatEvents: queue }, () => resolve());
    });
  });
}

/**
 * Drains offline event queue with bounded retries upon backend reconnection.
 */
async function drainPendingEventsQueue() {
  if (isDrainingQueue) return;
  isDrainingQueue = true;

  try {
    const token = await getAuthToken();
    if (!token) {
      isDrainingQueue = false;
      return;
    }

    const data = await new Promise((res) =>
      chrome.storage.local.get(["pendingThreatEvents"], res)
    );
    let queue = Array.isArray(data.pendingThreatEvents) ? data.pendingThreatEvents : [];
    if (queue.length === 0) {
      isDrainingQueue = false;
      return;
    }

    const remaining = [];
    for (const item of queue) {
      item.attempts = (item.attempts || 0) + 1;
      const { success, permanentError } = await transmitThreatEvent(item, token);

      if (success) {
        continue;
      }

      if (permanentError || item.attempts >= 5) {
        continue;
      }

      remaining.push(item);
    }

    await new Promise((res) =>
      chrome.storage.local.set({ pendingThreatEvents: remaining }, res)
    );
  } catch {
    // Non-fatal error during drain
  } finally {
    isDrainingQueue = false;
  }
}

function getAuthToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["authToken"], (res) => {
      let token = res.authToken || "";
      // In local development, fallback to development analyst token
      if (!token && (runtimeState.backendUrl.includes("localhost") || runtimeState.backendUrl.includes("127.0.0.1"))) {
        token = "dev-analyst-phase3";
      }
      resolve(token);
    });
  });
}

// Runtime message handler for popup and warning page
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === "get_status") {
    sendResponse({
      enabled: runtimeState.monitoringEnabled,
      backendUrl: runtimeState.backendUrl,
      backendConnected: runtimeState.backendConnected,
      localAgentEnabled: runtimeState.localAgentEnabled,
      recentEvents: runtimeState.recentEvents.slice(0, 10),
      policySyncMeta: runtimeState.policySyncMeta,
      policiesCount: runtimeState.domainPolicies.length,
    });
    return true;
  }

  if (message.action === "toggle_monitoring") {
    const newStatus = Boolean(message.enabled);
    runtimeState.monitoringEnabled = newStatus;
    chrome.storage.local.set({ monitoringEnabled: newStatus }, () => {
      updateBadge();
      sendResponse({ success: true, enabled: newStatus });
    });
    return true;
  }

  if (message.action === "dismiss_warning") {
    const domain = message.domain;
    if (domain) {
      runtimeState.dismissedDomains.add(domain.toLowerCase());
    }
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "clear_history") {
    runtimeState.recentEvents = [];
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "set_backend_url") {
    const rawUrl = message.url || "";
    if (!isValidBackendUrl(rawUrl)) {
      sendResponse({ success: false, error: "Invalid URL. Please specify a valid HTTP/HTTPS URL." });
      return true;
    }
    const cleanUrl = rawUrl.replace(/\/+$/, "");
    runtimeState.backendUrl = cleanUrl;
    chrome.storage.local.set({ backendUrl: cleanUrl }, () => {
      checkBackendHealth();
      void syncDomainPolicies();
      sendResponse({ success: true, backendUrl: cleanUrl });
    });
    return true;
  }

  if (message.action === "set_auth_token") {
    const token = typeof message.token === "string" ? message.token.trim() : "";
    chrome.storage.local.set({ authToken: token }, () => {
      checkBackendHealth();
      void syncDomainPolicies();
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.action === "sync_policies") {
    void syncDomainPolicies().then((res) => {
      sendResponse(res);
    });
    return true;
  }
});
