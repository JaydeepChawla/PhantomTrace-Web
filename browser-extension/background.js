/**
 * =====================================================================
 * PHANTOMTRACE WEB THREAT MONITOR — BACKGROUND SERVICE WORKER (V3)
 * =====================================================================
 * Privacy Guarantees:
 * 1. Checks ONLY domain/hostname. Never sends queries, passwords, or cookies.
 * 2. Conservative evaluation: Unknown domains are never marked malicious.
 * 3. Fail-safe: Timeouts or offline backend allow navigation without blocking.
 * 4. Deduplication: Prevents alert loops and respects user dismissals.
 * =====================================================================
 */

const DEFAULT_BACKEND_URL = "http://localhost:5000";
const LOCAL_AGENT_URL = "http://127.0.0.1:49152";

// In-memory runtime state
const runtimeState = {
  monitoringEnabled: false, // Explicit enablement required
  backendUrl: DEFAULT_BACKEND_URL,
  localAgentEnabled: true,
  backendConnected: false,
  dismissedDomains: new Set(),
  reputationCache: new Map(), // domain -> { result, expiresAt }
  recentEvents: [],
};

// Initialize settings from storage
chrome.storage.local.get(
  ["monitoringEnabled", "backendUrl", "localAgentEnabled"],
  (stored) => {
    if (typeof stored.monitoringEnabled === "boolean") {
      runtimeState.monitoringEnabled = stored.monitoringEnabled;
    } else {
      // Default: false until explicitly enabled by user in popup
      runtimeState.monitoringEnabled = false;
      chrome.storage.local.set({ monitoringEnabled: false });
    }

    if (stored.backendUrl && typeof stored.backendUrl === "string") {
      runtimeState.backendUrl = stored.backendUrl.replace(/\/+$/, "");
    }
    if (typeof stored.localAgentEnabled === "boolean") {
      runtimeState.localAgentEnabled = stored.localAgentEnabled;
    }
    updateBadge();
    checkBackendHealth();
  }
);

// Listen for storage changes
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.monitoringEnabled) {
    runtimeState.monitoringEnabled = changes.monitoringEnabled.newValue;
    updateBadge();
  }
  if (changes.backendUrl) {
    runtimeState.backendUrl = (changes.backendUrl.newValue || DEFAULT_BACKEND_URL).replace(/\/+$/, "");
    checkBackendHealth();
  }
  if (changes.localAgentEnabled) {
    runtimeState.localAgentEnabled = changes.localAgentEnabled.newValue;
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
  } catch {
    runtimeState.backendConnected = false;
  }
  updateBadge();
}

// Periodically check backend health every 60 seconds
setInterval(checkBackendHealth, 60000);

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

  // Check in-memory cache
  const cached = runtimeState.reputationCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    handleVerdict(cached.result, details);
    return;
  }

  // Query Backend Reputation Check API
  try {
    const controller = new AbortController();
    const timeoutTimer = setTimeout(() => controller.abort(), 2500);

    const res = await fetch(`${runtimeState.backendUrl}/api/web-threats/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
    const ttl = result.verdict === "BENIGN" || result.severity === "HIGH" || result.severity === "CRITICAL"
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

  // Active Threat (Phishing, Malware, Unwanted Software, or Suspicious Heuristic)
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
 * Syncs security event to backend REST API
 */
async function syncEventToBackend(result, url) {
  try {
    const token = await getAuthToken();
    if (!token) return;

    await fetch(`${runtimeState.backendUrl}/api/web-threats/events`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({
        domain: result.domain,
        url: url.split("?")[0], // Redact query params
        classification: result.verdict,
        severity: result.severity,
        score: result.score,
        confidence: result.confidence,
        detectionSource: result.source,
        ruleId: result.ruleId,
        explanation: result.explanation,
        browser: "Chrome/Edge Manifest V3",
      }),
    });
  } catch {
    // Backend sync error: non-fatal
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
    const url = (message.url || DEFAULT_BACKEND_URL).replace(/\/+$/, "");
    runtimeState.backendUrl = url;
    chrome.storage.local.set({ backendUrl: url }, () => {
      checkBackendHealth();
      sendResponse({ success: true });
    });
    return true;
  }
});
