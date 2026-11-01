function initPopup() {
  const enableToggle = document.getElementById("enableToggle");
  const statusIndicator = document.getElementById("statusIndicator");
  const backendBadge = document.getElementById("backendBadge");
  const backendUrlInput = document.getElementById("backendUrlInput");
  const saveBackendBtn = document.getElementById("saveBackendBtn");
  const backendErrorMsg = document.getElementById("backendErrorMsg");
  const threatsList = document.getElementById("threatsList");
  const clearHistoryBtn = document.getElementById("clearHistoryBtn");

  const authTokenInput = document.getElementById("authTokenInput");
  const saveTokenBtn = document.getElementById("saveTokenBtn");
  const tokenStatusBadge = document.getElementById("tokenStatusBadge");
  const tokenHelperMsg = document.getElementById("tokenHelperMsg");

  const policySyncBadge = document.getElementById("policySyncBadge");
  const policyRulesCount = document.getElementById("policyRulesCount");
  const policyLastSync = document.getElementById("policyLastSync");
  const policySyncMsg = document.getElementById("policySyncMsg");
  const syncPoliciesBtn = document.getElementById("syncPoliciesBtn");

  const DEFAULT_PRODUCTION_URL = "https://phantomtrace-web.onrender.com";

  function isValidUrl(str) {
    if (!str || typeof str !== "string") return false;
    try {
      const u = new URL(str.trim());
      return (u.protocol === "http:" || u.protocol === "https:") && Boolean(u.hostname);
    } catch {
      return false;
    }
  }

  function formatTime(isoStr) {
    if (!isoStr) return "Never";
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return "Never";
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch {
      return "Never";
    }
  }

  function refreshUI() {
    chrome.runtime.sendMessage({ action: "get_status" }, (response) => {
      if (!response) return;

      enableToggle.checked = Boolean(response.enabled);

      if (response.enabled) {
        statusIndicator.textContent = "Active";
        statusIndicator.className = "status-pill status-on";
      } else {
        statusIndicator.textContent = "Disabled";
        statusIndicator.className = "status-pill status-off";
      }

      backendUrlInput.value = response.backendUrl || DEFAULT_PRODUCTION_URL;

      // Load stored token
      chrome.storage.local.get(["authToken"], (res) => {
        const hasToken = Boolean(res.authToken && res.authToken.trim());
        if (authTokenInput && res.authToken) {
          authTokenInput.value = res.authToken;
        }

        const pMeta = response.policySyncMeta || {};

        if (tokenStatusBadge) {
          if (!hasToken) {
            tokenStatusBadge.textContent = "No Token";
            tokenStatusBadge.className = "badge badge-amber";
          } else if (pMeta.status === "AUTH_ERROR") {
            tokenStatusBadge.textContent = "Auth Failed";
            tokenStatusBadge.className = "badge badge-red";
          } else if (pMeta.status === "OFFLINE") {
            tokenStatusBadge.textContent = "Saved (Offline)";
            tokenStatusBadge.className = "badge badge-amber";
          } else if (pMeta.status === "SYNCED") {
            tokenStatusBadge.textContent = "Active";
            tokenStatusBadge.className = "badge badge-green";
          } else {
            tokenStatusBadge.textContent = "Configured";
            tokenStatusBadge.className = "badge badge-green";
          }
        }

        if (tokenHelperMsg) {
          if (!hasToken) {
            tokenHelperMsg.textContent = "Copy from Dashboard: Settings > Browser Extension, or Domain Policies > Connect Extension";
            tokenHelperMsg.style.color = "#64748b";
          } else if (pMeta.status === "AUTH_ERROR") {
            tokenHelperMsg.textContent = "Token rejected (401/403). Copy fresh token from Dashboard Settings or Domain Policies.";
            tokenHelperMsg.style.color = "#ef4444";
          } else if (pMeta.status === "SYNCED") {
            tokenHelperMsg.textContent = `Token active! Synchronized ${pMeta.blockCount || 0} Block | ${pMeta.allowCount || 0} Allow rule(s).`;
            tokenHelperMsg.style.color = "#10b981";
          } else if (pMeta.status === "OFFLINE") {
            tokenHelperMsg.textContent = "Token saved locally. Backend offline / unreachable; local policies preserved.";
            tokenHelperMsg.style.color = "#f59e0b";
          }
        }
      });

      if (response.backendConnected) {
        backendBadge.textContent = "Connected";
        backendBadge.className = "badge badge-green";
      } else {
        backendBadge.textContent = "Offline / Error";
        backendBadge.className = "badge badge-amber";
      }

      // Domain Policies state
      const pMeta = response.policySyncMeta || {};
      const blockCount = typeof pMeta.blockCount === "number" ? pMeta.blockCount : 0;
      const allowCount = typeof pMeta.allowCount === "number" ? pMeta.allowCount : 0;

      if (policyRulesCount) {
        policyRulesCount.textContent = `${blockCount} Block | ${allowCount} Allow`;
      }

      if (policyLastSync) {
        policyLastSync.textContent = formatTime(pMeta.lastSyncTime);
      }

      if (policySyncBadge) {
        if (pMeta.status === "SYNCED") {
          policySyncBadge.textContent = "Synced";
          policySyncBadge.className = "badge badge-green";
        } else if (pMeta.status === "AUTH_REQUIRED") {
          policySyncBadge.textContent = "Auth Required";
          policySyncBadge.className = "badge badge-amber";
        } else if (pMeta.status === "OFFLINE") {
          policySyncBadge.textContent = "Offline";
          policySyncBadge.className = "badge badge-amber";
        } else if (pMeta.status === "AUTH_ERROR") {
          policySyncBadge.textContent = "Token Error";
          policySyncBadge.className = "badge badge-red";
        } else {
          policySyncBadge.textContent = "Idle";
          policySyncBadge.className = "badge badge-amber";
        }
      }

      if (policySyncMsg) {
        if (pMeta.errorMessage) {
          policySyncMsg.textContent = pMeta.errorMessage;
          policySyncMsg.style.display = "block";
        } else {
          policySyncMsg.style.display = "none";
        }
      }

      renderThreats(response.recentEvents || []);
    });
  }

  function renderThreats(events) {
    if (!events || events.length === 0) {
      threatsList.innerHTML = `<div class="empty-state">No web threats detected. Safe browsing active.</div>`;
      return;
    }

    threatsList.innerHTML = events
      .map((ev) => {
        const severityClass =
          ev.severity === "CRITICAL" || ev.severity === "HIGH"
            ? "badge-red"
            : "badge-amber";

        return `
          <div class="threat-item">
            <span class="threat-domain" title="${escapeHtml(ev.domain)}">${escapeHtml(ev.domain)}</span>
            <span class="badge ${severityClass}">${escapeHtml(ev.verdict || "THREAT")}</span>
          </div>
        `;
      })
      .join("");
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  enableToggle.addEventListener("change", (e) => {
    const isEnabled = e.target.checked;
    chrome.runtime.sendMessage({ action: "toggle_monitoring", enabled: isEnabled }, () => {
      refreshUI();
    });
  });

  saveBackendBtn.addEventListener("click", () => {
    const rawUrl = backendUrlInput.value.trim();
    if (!isValidUrl(rawUrl)) {
      if (backendErrorMsg) {
        backendErrorMsg.textContent = "Please enter a valid HTTP or HTTPS URL (e.g. https://phantomtrace-web.onrender.com).";
        backendErrorMsg.style.display = "block";
      }
      return;
    }

    if (backendErrorMsg) {
      backendErrorMsg.style.display = "none";
    }

    chrome.runtime.sendMessage({ action: "set_backend_url", url: rawUrl }, (res) => {
      if (res && res.error) {
        if (backendErrorMsg) {
          backendErrorMsg.textContent = res.error;
          backendErrorMsg.style.display = "block";
        }
      } else {
        refreshUI();
      }
    });
  });

  if (saveTokenBtn) {
    saveTokenBtn.addEventListener("click", () => {
      const rawToken = authTokenInput.value || "";
      const token = rawToken.trim().replace(/^["']|["']$/g, "");
      if (!token) {
        if (tokenHelperMsg) {
          tokenHelperMsg.textContent = "Please paste your token from the dashboard.";
          tokenHelperMsg.style.color = "#f87171";
        }
        return;
      }

      saveTokenBtn.disabled = true;
      saveTokenBtn.textContent = "Setting...";
      if (tokenHelperMsg) {
        tokenHelperMsg.textContent = "Saving token & synchronizing policies...";
        tokenHelperMsg.style.color = "#00e5ff";
      }

      chrome.runtime.sendMessage({ action: "set_auth_token", token }, () => {
        chrome.runtime.sendMessage({ action: "sync_policies" }, (syncRes) => {
          saveTokenBtn.disabled = false;
          saveTokenBtn.textContent = "Set";
          if (syncRes && syncRes.status === "SYNCED") {
            if (tokenHelperMsg) {
              tokenHelperMsg.textContent = `Token active! Synchronized ${syncRes.policiesCount || 0} policy rule(s).`;
              tokenHelperMsg.style.color = "#10b981";
            }
          } else if (syncRes && syncRes.status === "AUTH_ERROR") {
            if (tokenHelperMsg) {
              tokenHelperMsg.textContent = "Token rejected by backend (401/403). Copy a fresh token from Dashboard.";
              tokenHelperMsg.style.color = "#ef4444";
            }
          } else if (syncRes && syncRes.status === "OFFLINE") {
            if (tokenHelperMsg) {
              tokenHelperMsg.textContent = "Token saved, but backend is offline. Local policies preserved.";
              tokenHelperMsg.style.color = "#f59e0b";
            }
          } else {
            if (tokenHelperMsg) {
              tokenHelperMsg.textContent = "Token saved. Click 'Sync Policies' to verify.";
              tokenHelperMsg.style.color = "#94a3b8";
            }
          }
          refreshUI();
        });
      });
    });
  }

  if (syncPoliciesBtn) {
    syncPoliciesBtn.addEventListener("click", () => {
      syncPoliciesBtn.disabled = true;
      syncPoliciesBtn.textContent = "Syncing...";
      chrome.runtime.sendMessage({ action: "sync_policies" }, (res) => {
        syncPoliciesBtn.disabled = false;
        syncPoliciesBtn.textContent = "Sync Policies";
        if (policySyncMsg) {
          if (res && res.status === "SYNCED") {
            policySyncMsg.textContent = `Policies synchronized successfully (${res.policiesCount || 0} active rule${res.policiesCount === 1 ? '' : 's'}).`;
            policySyncMsg.style.color = "#10b981";
            policySyncMsg.style.display = "block";
          } else if (res && res.status === "AUTH_REQUIRED") {
            policySyncMsg.textContent = "Authentication required. Please set an extension token above.";
            policySyncMsg.style.color = "#f59e0b";
            policySyncMsg.style.display = "block";
          } else if (res && res.status === "AUTH_ERROR") {
            policySyncMsg.textContent = "Authentication failed (401/403). Generate a fresh token from Dashboard.";
            policySyncMsg.style.color = "#ef4444";
            policySyncMsg.style.display = "block";
          } else if (res && res.status === "OFFLINE") {
            policySyncMsg.textContent = "Backend offline or unreachable. Existing local policies preserved.";
            policySyncMsg.style.color = "#f59e0b";
            policySyncMsg.style.display = "block";
          }
        }
        refreshUI();
      });
    });
  }

  clearHistoryBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "clear_history" }, () => {
      refreshUI();
    });
  });

  // Initial load
  refreshUI();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initPopup);
} else {
  initPopup();
}
