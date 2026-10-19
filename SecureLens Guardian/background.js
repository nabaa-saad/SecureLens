const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const WARNING_BYPASS_MS = 30 * 60 * 1000;
const MAX_HISTORY_GROUPS = 24;
const MAX_HISTORY_VISITS_PER_DOMAIN = 8;

const STORAGE_KEYS = {
  backendBaseUrl: "backendBaseUrl",
  sessionToken: "sessionToken",
  sessionUser: "sessionUser",
  scanStates: "scanStates",
  scanHistory: "scanHistory",
  warningBypasses: "warningBypasses",
};

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.backendBaseUrl);
  if (!stored[STORAGE_KEYS.backendBaseUrl]) {
    await chrome.storage.local.set({ [STORAGE_KEYS.backendBaseUrl]: DEFAULT_API_BASE_URL });
  }
});

function isScannableUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isRiskyVerdict(result) {
  const verdict = String(result?.verdict || "").toLowerCase();
  if (verdict === "malicious") {
    return true;
  }
  if (verdict !== "suspicious") {
    return false;
  }

  // Only interrupt navigation for suspicious results when the backend also
  // has concrete evidence, not just a weak or stale cached classification.
  const malicious = Number(result?.virus_total?.malicious_count ?? 0);
  const suspicious = Number(result?.virus_total?.suspicious_count ?? 0);
  const riskScore = Number(result?.risk_score ?? 0);
  return malicious > 0 || suspicious > 0 || riskScore >= 70;
}

function buildWarningUrl(tabId, currentUrl, result) {
  const params = new URLSearchParams({
    tabId: String(tabId),
    url: currentUrl,
    canonical_domain: result.canonical_domain || "",
    verdict: result.verdict || "suspicious",
    risk_score: String(result.risk_score ?? 0),
    malicious_count: String(result.virus_total?.malicious_count ?? 0),
    suspicious_count: String(result.virus_total?.suspicious_count ?? 0),
    harmless_count: String(result.virus_total?.harmless_count ?? 0),
    total_engines: String(result.virus_total?.total_engines ?? 0),
    deep_scan_path: result.deep_scan_path || "",
  });
  return `${chrome.runtime.getURL("warning.html")}?${params.toString()}`;
}

async function getConfig() {
  const values = await chrome.storage.local.get([
    STORAGE_KEYS.backendBaseUrl,
    STORAGE_KEYS.sessionToken,
    STORAGE_KEYS.scanStates,
    STORAGE_KEYS.scanHistory,
    STORAGE_KEYS.warningBypasses,
  ]);
  return {
    backendBaseUrl: values[STORAGE_KEYS.backendBaseUrl] || DEFAULT_API_BASE_URL,
    sessionToken: values[STORAGE_KEYS.sessionToken] || "",
    scanStates: values[STORAGE_KEYS.scanStates] || {},
    scanHistory: values[STORAGE_KEYS.scanHistory] || {},
    warningBypasses: values[STORAGE_KEYS.warningBypasses] || {},
  };
}

async function saveScanState(tabId, state) {
  const { scanStates } = await getConfig();
  scanStates[String(tabId)] = { ...state, tabId, updatedAtMs: Date.now() };
  await chrome.storage.local.set({ [STORAGE_KEYS.scanStates]: scanStates });
}

async function getScanState(tabId) {
  const { scanStates } = await getConfig();
  return scanStates[String(tabId)] || null;
}

async function clearScanState(tabId) {
  const { scanStates } = await getConfig();
  delete scanStates[String(tabId)];
  await chrome.storage.local.set({ [STORAGE_KEYS.scanStates]: scanStates });
}

async function clearSession() {
  await chrome.storage.local.remove([STORAGE_KEYS.sessionToken, STORAGE_KEYS.sessionUser]);
}

async function clearBadge(tabId) {
  if (!tabId) return;
  await chrome.action.setBadgeText({ tabId, text: "" });
}

async function setBadge(tabId, result) {
  if (!tabId) return;

  const verdict = (result?.verdict || "").toUpperCase();
  if (!result || !verdict) {
    await clearBadge(tabId);
    return;
  }

  let text = "SAFE";
  let color = "#059669";
  if (verdict === "MALICIOUS") {
    text = "MAL";
    color = "#dc2626";
  } else if (verdict === "SUSPICIOUS") {
    text = "WARN";
    color = "#d97706";
  }

  await chrome.action.setBadgeBackgroundColor({ tabId, color });
  await chrome.action.setBadgeText({ tabId, text });
}

async function pruneWarningBypasses() {
  const { warningBypasses } = await getConfig();
  const now = Date.now();
  const next = {};
  Object.entries(warningBypasses).forEach(([url, expiresAtMs]) => {
    if (Number(expiresAtMs) > now) {
      next[url] = Number(expiresAtMs);
    }
  });
  await chrome.storage.local.set({ [STORAGE_KEYS.warningBypasses]: next });
  return next;
}

async function allowWarningBypass(url) {
  const next = await pruneWarningBypasses();
  next[url] = Date.now() + WARNING_BYPASS_MS;
  await chrome.storage.local.set({ [STORAGE_KEYS.warningBypasses]: next });
}

async function hasWarningBypass(url) {
  const next = await pruneWarningBypasses();
  return Boolean(next[url] && next[url] > Date.now());
}

async function rememberScanHistory(currentUrl, result) {
  if (!currentUrl || !result?.canonical_domain) return;

  const { scanHistory } = await getConfig();
  const key = result.canonical_domain;
  const now = Date.now();
  const existing = scanHistory[key] || {
    canonicalDomain: key,
    visits: [],
  };

  const filteredVisits = (existing.visits || []).filter((item) => item.url !== currentUrl);
  filteredVisits.unshift({
    url: currentUrl,
    label: result.original_input || currentUrl,
    verdict: result.verdict || "suspicious",
    riskScore: Number(result.risk_score ?? 0),
    updatedAtMs: now,
    scanId: result.scan_id || null,
    deepScanPath: result.deep_scan_path || "",
  });

  scanHistory[key] = {
    canonicalDomain: key,
    verdict: result.verdict || "suspicious",
    riskScore: Number(result.risk_score ?? 0),
    updatedAtMs: now,
    deepScanPath: result.deep_scan_path || existing.deepScanPath || "",
    visits: filteredVisits.slice(0, MAX_HISTORY_VISITS_PER_DOMAIN),
  };

  const sortedGroups = Object.values(scanHistory)
    .sort((a, b) => Number(b.updatedAtMs || 0) - Number(a.updatedAtMs || 0))
    .slice(0, MAX_HISTORY_GROUPS);

  const trimmed = {};
  sortedGroups.forEach((group) => {
    trimmed[group.canonicalDomain] = group;
  });

  await chrome.storage.local.set({ [STORAGE_KEYS.scanHistory]: trimmed });
}

async function getHistoryTree() {
  const { scanHistory } = await getConfig();
  return Object.values(scanHistory).sort((a, b) => Number(b.updatedAtMs || 0) - Number(a.updatedAtMs || 0));
}

async function deleteHistoryDomain(domain) {
  const { scanHistory } = await getConfig();
  delete scanHistory[domain];
  await chrome.storage.local.set({ [STORAGE_KEYS.scanHistory]: scanHistory });
}

async function deleteHistoryVisit(domain, url) {
  const { scanHistory } = await getConfig();
  const group = scanHistory[domain];
  if (!group) return;
  group.visits = (group.visits || []).filter((visit) => visit.url !== url);
  if (!group.visits.length) {
    delete scanHistory[domain];
  } else {
    group.updatedAtMs = Number(group.visits[0]?.updatedAtMs || Date.now());
    group.verdict = group.visits[0]?.verdict || group.verdict;
    group.riskScore = Number(group.visits[0]?.riskScore ?? group.riskScore ?? 0);
    scanHistory[domain] = group;
  }
  await chrome.storage.local.set({ [STORAGE_KEYS.scanHistory]: scanHistory });
}

async function handleApiAuthFailure(tabId) {
  await clearSession();
  if (tabId) {
    await saveScanState(tabId, {
      status: "disconnected",
      error: "Your website session has expired. Reconnect the extension.",
    });
    await clearBadge(tabId);
  }
}

async function fetchExtensionApi(path, options = {}) {
  const { backendBaseUrl, sessionToken } = await getConfig();
  const headers = new Headers(options.headers || {});
  if (sessionToken) {
    headers.set("Authorization", `Bearer ${sessionToken}`);
  }
  const response = await fetch(`${backendBaseUrl}${path}`, {
    ...options,
    headers,
  });
  return { response, backendBaseUrl };
}

async function maybeShowWarning(tabId, currentUrl, data) {
  if (!isRiskyVerdict(data) || !currentUrl) {
    return;
  }
  if (await hasWarningBypass(currentUrl)) {
    return;
  }

  await saveScanState(tabId, { ...data, currentUrl, warningActive: true });
  await chrome.tabs.update(tabId, {
    url: buildWarningUrl(tabId, currentUrl, data),
  });
}

async function finalizeCompletedScan(tabId, currentUrl, data) {
  const state = { ...data, currentUrl, warningActive: false };
  await saveScanState(tabId, state);
  await setBadge(tabId, data);
  await rememberScanHistory(currentUrl, data);
  await maybeShowWarning(tabId, currentUrl, data);
}

async function pollScan(tabId, scanId, currentUrl, attempt = 0) {
  if (attempt > 40) {
    await saveScanState(tabId, {
      status: "error",
      currentUrl,
      error: "The quick scan timed out. Open the popup to try again.",
    });
    return;
  }

  try {
    const { response } = await fetchExtensionApi(`/api/extension/scans/${scanId}`);
    if (response.status === 401) {
      await handleApiAuthFailure(tabId);
      return;
    }
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      await saveScanState(tabId, {
        status: "error",
        currentUrl,
        error: error.detail || "Failed to fetch scan status.",
      });
      return;
    }

    const data = await response.json();
    if (data.status === "pending") {
      await saveScanState(tabId, { ...data, currentUrl });
      setTimeout(() => pollScan(tabId, scanId, currentUrl, attempt + 1), 1800);
      return;
    }

    await finalizeCompletedScan(tabId, currentUrl, data);
  } catch {
    await saveScanState(tabId, {
      status: "error",
      currentUrl,
      error: "Unable to contact the SecureLens backend.",
    });
  }
}

async function requestQuickScan(tabId, url) {
  if (!isScannableUrl(url)) {
    await clearScanState(tabId);
    await clearBadge(tabId);
    return;
  }

  const { sessionToken } = await getConfig();
  if (!sessionToken) {
    await saveScanState(tabId, {
      status: "disconnected",
      currentUrl: url,
      error: "Connect the extension from the popup to start scanning.",
    });
    await clearBadge(tabId);
    return;
  }

  await saveScanState(tabId, { status: "pending", currentUrl: url });

  try {
    const { response } = await fetchExtensionApi("/api/extension/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (response.status === 401) {
      await handleApiAuthFailure(tabId);
      return;
    }

    const data = await response.json();
    if (!response.ok) {
      await saveScanState(tabId, {
        status: "error",
        currentUrl: url,
        error: data.detail || "Quick scan failed.",
      });
      return;
    }

    if (data.status === "pending") {
      await saveScanState(tabId, { ...data, currentUrl: url });
      setTimeout(() => pollScan(tabId, data.scan_id, url), 1200);
      return;
    }

    await finalizeCompletedScan(tabId, url, data);
  } catch {
    await saveScanState(tabId, {
      status: "error",
      currentUrl: url,
      error: "Unable to contact the SecureLens backend.",
    });
  }
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab?.url) {
    requestQuickScan(tabId, tab.url);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    requestQuickScan(tabId, tab.url);
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await clearScanState(tabId);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "force-scan") {
    requestQuickScan(message.tabId, message.url).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message?.type === "get-scan-state") {
    getScanState(message.tabId).then((state) => sendResponse(state));
    return true;
  }

  if (message?.type === "clear-session") {
    clearSession().then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message?.type === "get-history") {
    getHistoryTree().then((history) => sendResponse(history));
    return true;
  }

  if (message?.type === "delete-history-domain") {
    deleteHistoryDomain(message.domain).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message?.type === "delete-history-visit") {
    deleteHistoryVisit(message.domain, message.url).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message?.type === "proceed-warning") {
    allowWarningBypass(message.url)
      .then(() => chrome.tabs.update(message.tabId, { url: message.url }))
      .then(() => sendResponse({ ok: true }));
    return true;
  }

  return false;
});
