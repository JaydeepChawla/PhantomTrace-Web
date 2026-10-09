function initWarning() {
  const params = new URLSearchParams(window.location.search);

  const domain = params.get("domain") || "unknown-domain.com";
  const targetUrl = params.get("target") || `https://${domain}`;
  const severity = (params.get("severity") || "HIGH").toUpperCase();
  const verdict = (params.get("verdict") || "POTENTIAL_THREAT").replace(/_/g, " ");
  const source = (params.get("source") || "THREAT_INTEL").replace(/_/g, " ");
  const ruleId = params.get("ruleId") || "RULE-DEFAULT";
  const explanation =
    params.get("explanation") ||
    "This website has been flagged by PhantomTrace threat intelligence or heuristic security patterns.";

  // Elements
  const severityBadge = document.getElementById("severityBadge");
  const warningTitle = document.getElementById("warningTitle");
  const domainDisplay = document.getElementById("domainDisplay");
  const classificationVal = document.getElementById("classificationVal");
  const sourceVal = document.getElementById("sourceVal");
  const ruleVal = document.getElementById("ruleVal");
  const explanationVal = document.getElementById("explanationVal");
  const safeBtn = document.getElementById("safeBtn");
  const proceedBtn = document.getElementById("proceedBtn");

  // Populate data using textContent to prevent injection
  domainDisplay.textContent = domain;
  classificationVal.textContent = verdict;
  sourceVal.textContent = source;
  ruleVal.textContent = ruleId;
  explanationVal.textContent = explanation;

  if (severity === "CRITICAL") {
    severityBadge.className = "badge badge-critical";
    severityBadge.textContent = "CRITICAL THREAT";
    warningTitle.textContent = "Malicious Website Blocked";
  } else if (severity === "HIGH") {
    severityBadge.className = "badge badge-high";
    severityBadge.textContent = "HIGH SEVERITY";
    warningTitle.textContent = "Phishing or Threat Detected";
  } else {
    severityBadge.className = "badge badge-medium";
    severityBadge.textContent = "SUSPICIOUS WEBSITE";
    warningTitle.textContent = "Potentially Deceptive Website";
  }

  // Back to safety action
  safeBtn.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // Proceed anyway action (dismiss warning for this domain)
  proceedBtn.addEventListener("click", () => {
    try {
      chrome.runtime.sendMessage(
        { action: "dismiss_warning", domain },
        () => {
          // Navigate to original destination
          window.location.href = targetUrl;
        }
      );
    } catch {
      window.location.href = targetUrl;
    }
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initWarning);
} else {
  initWarning();
}
