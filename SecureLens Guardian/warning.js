const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

function getParam(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
}

async function getBackendBaseUrl() {
  const values = await chrome.storage.local.get("backendBaseUrl");
  return values.backendBaseUrl || DEFAULT_API_BASE_URL;
}

function clearChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function setConfidenceTone(node, tone) {
  node.classList.remove("confidence-pill--high", "confidence-pill--medium", "confidence-pill--low");
  node.classList.add(
    tone === "high" ? "confidence-pill--high" : tone === "medium" ? "confidence-pill--medium" : "confidence-pill--low",
  );
}

function appendSignal(container, signal) {
  const item = document.createElement("article");
  item.className = `signal-item signal-item--${signal.severity}`;

  const title = document.createElement("span");
  title.className = "signal-item__title";
  title.textContent = signal.title;

  const copy = document.createElement("span");
  copy.className = "signal-item__copy";
  copy.textContent = signal.detail;

  item.append(title, copy);
  container.appendChild(item);
}

function appendAction(container, actionText) {
  const item = document.createElement("article");
  item.className = "action-item";

  const title = document.createElement("span");
  title.className = "action-item__title";
  title.textContent = "Recommended action";

  const copy = document.createElement("span");
  copy.className = "action-item__copy";
  copy.textContent = actionText;

  item.append(title, copy);
  container.appendChild(item);
}

function renderDecisionPoints(container, verdict, actions) {
  clearChildren(container);

  const points = [];
  if (verdict === "malicious") {
    points.push("Recommended: close this tab and reopen the real service from a trusted bookmark or manually typed address.");
  } else if (verdict === "suspicious") {
    points.push("Recommended: do not sign in, pay, or download anything until the site is verified.");
  } else {
    points.push("Proceed only if this destination was expected and nothing about the page feels unusual.");
  }

  actions.slice(0, 2).forEach((action) => {
    points.push(action);
  });

  points.forEach((text) => {
    const item = document.createElement("div");
    item.className = "decision-point";
    item.textContent = text;
    container.appendChild(item);
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  const verdict = (getParam("verdict") || "suspicious").toLowerCase();
  const riskScore = Number(getParam("risk_score") || "0");
  const maliciousCount = Number(getParam("malicious_count") || "0");
  const suspiciousCount = Number(getParam("suspicious_count") || "0");
  const totalEngines = Number(getParam("total_engines") || "0");
  const canonicalDomain = getParam("canonical_domain");
  const url = getParam("url");
  const tabId = Number(getParam("tabId") || "0");
  const deepScanPath = getParam("deep_scan_path");

  const warningCard = document.getElementById("warningCard");
  const confidenceValue = document.getElementById("confidenceValue");
  const reportBtn = document.getElementById("reportBtn");
  const signalList = document.getElementById("signalList");
  const actionList = document.getElementById("actionList");
  const decisionHeadline = document.getElementById("decisionHeadline");
  const decisionCopy = document.getElementById("decisionCopy");
  const decisionPoints = document.getElementById("decisionPoints");

  const intel = window.SecureLensIntel?.analyzeScan({
    verdict,
    risk_score: riskScore,
    canonical_domain: canonicalDomain,
    original_input: url,
    virus_total: {
      malicious_count: maliciousCount,
      suspicious_count: suspiciousCount,
      harmless_count: 0,
      total_engines: totalEngines,
      detection_ratio: `${maliciousCount + suspiciousCount}/${totalEngines || 0}`,
    },
  });

  warningCard.dataset.verdict = verdict;
  document.getElementById("warningTitle").textContent =
    intel?.headline || "Review this site before continuing";
  document.getElementById("warningCopy").textContent =
    intel?.summary || "SecureLens found signals that deserve a second look before this page is trusted.";
  document.getElementById("summaryValue").textContent =
    intel?.summary || "No additional explanation available.";
  document.getElementById("verdictValue").textContent = verdict.toUpperCase();
  document.getElementById("riskValue").textContent = `${riskScore}%`;
  document.getElementById("engineValue").textContent = intel?.detectionRatio || `${totalEngines} checked`;
  document.getElementById("portsValue").textContent = intel?.portsSummary || "No recent port telemetry";
  document.getElementById("domainValue").textContent = canonicalDomain || "-";
  document.getElementById("urlValue").textContent = url || "-";

  confidenceValue.textContent = intel?.confidence?.label || "Baseline confidence";
  setConfidenceTone(confidenceValue, intel?.confidence?.tone || "low");

  decisionHeadline.textContent =
    verdict === "malicious"
      ? "Leave this site now and verify the address separately."
      : verdict === "suspicious"
        ? "Pause here until the destination is verified."
        : "Proceed only if this destination was expected.";
  decisionCopy.textContent =
    verdict === "malicious"
      ? "The quick evidence is strong enough that SecureLens is treating this page as unsafe until proven otherwise."
      : verdict === "suspicious"
        ? "The destination is not confirmed malicious, but the current evidence is weak enough that trust would be premature."
        : "The page is probably acceptable, but SecureLens still wants you to make an intentional decision before continuing.";
  renderDecisionPoints(decisionPoints, verdict, intel?.actions || []);

  clearChildren(signalList);
  if (intel?.signals?.length) {
    intel.signals.forEach((signal) => appendSignal(signalList, signal));
  } else {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "SecureLens could not build a local signal breakdown for this warning.";
    signalList.appendChild(empty);
  }

  clearChildren(actionList);
  if (intel?.actions?.length) {
    intel.actions.forEach((actionText) => appendAction(actionList, actionText));
  } else {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Use the full AI report for a deeper decision before continuing.";
    actionList.appendChild(empty);
  }

  reportBtn.classList.toggle("hidden", !deepScanPath);

  document.getElementById("backBtn").addEventListener("click", async () => {
    if (tabId) {
      await chrome.tabs.remove(tabId).catch(async () => {
        await chrome.tabs.update(tabId, { url: "about:blank" });
      });
      return;
    }
    window.location.replace("about:blank");
  });

  document.getElementById("continueBtn").addEventListener("click", async () => {
    if (!tabId || !url) return;
    await chrome.runtime.sendMessage({ type: "proceed-warning", tabId, url });
  });

  document.getElementById("reportBtn").addEventListener("click", async () => {
    if (!deepScanPath) return;
    const backendBaseUrl = await getBackendBaseUrl();
    await chrome.tabs.create({ url: `${backendBaseUrl}${deepScanPath}` });
  });
});
