function initPopup() {
  const enableToggle = document.getElementById("enableToggle");
  const statusIndicator = document.getElementById("statusIndicator");
  const backendBadge = document.getElementById("backendBadge");
  const backendUrlInput = document.getElementById("backendUrlInput");
  const saveBackendBtn = document.getElementById("saveBackendBtn");
  const threatsList = document.getElementById("threatsList");
  const clearHistoryBtn = document.getElementById("clearHistoryBtn");

  const authTokenInput = document.getElementById("authTokenInput");
  const saveTokenBtn = document.getElementById("saveTokenBtn");

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

      backendUrlInput.value = response.backendUrl || "http://localhost:5000";

      // Load stored token
      chrome.storage.local.get(["authToken"], (res) => {
        if (authTokenInput && res.authToken) {
          authTokenInput.value = res.authToken;
        }
      });

      if (response.backendConnected) {
        backendBadge.textContent = "Connected";
        backendBadge.className = "badge badge-green";
      } else {
        backendBadge.textContent = "Offline / Error";
        backendBadge.className = "badge badge-amber";
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
    const newUrl = backendUrlInput.value.trim();
    if (!newUrl) return;
    chrome.runtime.sendMessage({ action: "set_backend_url", url: newUrl }, () => {
      refreshUI();
    });
  });

  if (saveTokenBtn) {
    saveTokenBtn.addEventListener("click", () => {
      const token = authTokenInput.value.trim();
      chrome.storage.local.set({ authToken: token }, () => {
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
