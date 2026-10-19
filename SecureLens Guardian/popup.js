const DEFAULT_API_BASE_URL = "http://localhost:8000";

const STORAGE_KEYS = {
  backendBaseUrl: "backendBaseUrl",
  sessionToken: "sessionToken",
  sessionUser: "sessionUser",
  pendingPairing: "pendingPairing",
};

let activeTab = null;
let activeScan = null;
let selectedProvider = "ollama";
let pendingPollTimer = null;
let currentSessionUser = null;
let activeSection = "main";
let historySnapshot = [];
let historySearchQuery = "";

const ui = {};

document.addEventListener("DOMContentLoaded", async () => {
  bindUi();
  renderProtectionPulse();
  renderScanTimeline();
  renderAssistantContext();
  setChatAvailability(false, "Finish a scan to ask for an explanation, risks, or next steps.");
  await ensureBackendBaseUrl();
  await hydrateSession();
  await loadHistoryTree();
  await loadActiveTab();
  switchTab(activeSection);
});

function bindUi() {
  ui.tabButtons = Array.from(document.querySelectorAll("[data-tab-target]"));
  ui.switchTabButtons = Array.from(document.querySelectorAll("[data-switch-tab]"));
  ui.tabPanels = {
    main: document.getElementById("tab-main"),
    assistant: document.getElementById("tab-assistant"),
    tree: document.getElementById("tab-tree"),
    account: document.getElementById("tab-account"),
  };
  ui.headerSessionBadge = document.getElementById("headerSessionBadge");
  ui.headerPageBadge = document.getElementById("headerPageBadge");
  ui.sessionHeadline = document.getElementById("sessionHeadline");
  ui.sessionSubtle = document.getElementById("sessionSubtle");
  ui.accountUsername = document.getElementById("accountUsername");
  ui.accountEmail = document.getElementById("accountEmail");
  ui.accountStatus = document.getElementById("accountStatus");
  ui.connectBtn = document.getElementById("connectBtn");
  ui.disconnectBtn = document.getElementById("disconnectBtn");
  ui.pairingCard = document.getElementById("pairingCard");
  ui.pairingStatus = document.getElementById("pairingStatus");
  ui.scanCard = document.getElementById("scanCard");
  ui.chatCard = document.getElementById("chatCard");
  ui.messageCard = document.getElementById("messageCard");
  ui.messageText = document.getElementById("messageText");
  ui.domainValue = document.getElementById("domainValue");
  ui.scanUrlValue = document.getElementById("scanUrlValue");
  ui.refreshBtn = document.getElementById("refreshBtn");
  ui.historyRefreshBtn = document.getElementById("historyRefreshBtn");
  ui.historySearch = document.getElementById("historySearch");
  ui.verdictBox = document.getElementById("verdictBox");
  ui.verdictLabel = document.getElementById("verdictLabel");
  ui.verdictHelp = document.getElementById("verdictHelp");
  ui.verdictScore = document.getElementById("verdictScore");
  ui.scanStatePill = document.getElementById("scanStatePill");
  ui.scanDetectionRatio = document.getElementById("scanDetectionRatio");
  ui.vtMalicious = document.getElementById("vtMalicious");
  ui.vtSuspicious = document.getElementById("vtSuspicious");
  ui.vtHarmless = document.getElementById("vtHarmless");
  ui.vtTotal = document.getElementById("vtTotal");
  ui.openReportBtn = document.getElementById("openReportBtn");
  ui.intelCard = document.getElementById("intelCard");
  ui.intelHeadline = document.getElementById("intelHeadline");
  ui.intelConfidence = document.getElementById("intelConfidence");
  ui.intelSummary = document.getElementById("intelSummary");
  ui.signalList = document.getElementById("signalList");
  ui.actionList = document.getElementById("actionList");
  ui.factGrid = document.getElementById("factGrid");
  ui.portsSummary = document.getElementById("portsSummary");
  ui.timelineList = document.getElementById("timelineList");
  ui.pulseSummary = document.getElementById("pulseSummary");
  ui.pulseAccount = document.getElementById("pulseAccount");
  ui.pulsePage = document.getElementById("pulsePage");
  ui.pulseDecision = document.getElementById("pulseDecision");
  ui.pulseReport = document.getElementById("pulseReport");
  ui.historyTree = document.getElementById("historyTree");
  ui.historyDomainCount = document.getElementById("historyDomainCount");
  ui.historyRiskCount = document.getElementById("historyRiskCount");
  ui.historyVisitCount = document.getElementById("historyVisitCount");
  ui.providerSelect = document.getElementById("providerSelect");
  ui.chatAvailabilityText = document.getElementById("chatAvailabilityText");
  ui.chatLog = document.getElementById("chatLog");
  ui.chatEmpty = document.getElementById("chatEmpty");
  ui.chatForm = document.getElementById("chatForm");
  ui.chatInput = document.getElementById("chatInput");
  ui.chatSendBtn = document.getElementById("chatSendBtn");
  ui.promptButtons = Array.from(document.querySelectorAll(".prompt-chip"));
  ui.assistantHeadline = document.getElementById("assistantHeadline");
  ui.assistantSummary = document.getElementById("assistantSummary");
  ui.assistantVerdictBadge = document.getElementById("assistantVerdictBadge");
  ui.assistantFactGrid = document.getElementById("assistantFactGrid");

  ui.tabButtons.forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset.tabTarget || "main"));
  });
  ui.switchTabButtons.forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset.switchTab || "main"));
  });
  ui.connectBtn.addEventListener("click", startPairing);
  ui.disconnectBtn.addEventListener("click", disconnectExtension);
  ui.refreshBtn.addEventListener("click", () => forceQuickScan(true));
  ui.historyRefreshBtn.addEventListener("click", loadHistoryTree);
  ui.historySearch.addEventListener("input", (event) => {
    historySearchQuery = (event.target.value || "").trim().toLowerCase();
    renderHistoryTree(historySnapshot);
  });
  ui.openReportBtn.addEventListener("click", openFullReport);
  ui.providerSelect.addEventListener("change", async (event) => {
    selectedProvider = event.target.value;
    if (activeScan?.scan_id) {
      await loadChatHistory();
    }
  });
  ui.chatForm.addEventListener("submit", sendChatMessage);

  ui.promptButtons.forEach((button) => {
    button.addEventListener("click", () => {
      if (button.disabled) return;
      ui.chatInput.value = button.dataset.prompt || "";
      ui.chatInput.focus();
    });
  });

  ui.historyTree.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-history-action]");
    if (!button) return;
    event.preventDefault();
    event.stopPropagation();

    const action = button.dataset.historyAction;
    const domain = button.dataset.domain || "";
    const url = button.dataset.url || "";
    const reportPath = button.dataset.reportPath || "";

    if (action === "open" && url) {
      await chrome.tabs.create({ url });
      return;
    }

    if (action === "report" && reportPath) {
      await openReportPath(reportPath);
      return;
    }

    if (action === "delete-domain" && domain) {
      await chrome.runtime.sendMessage({ type: "delete-history-domain", domain });
      await loadHistoryTree();
      return;
    }

    if (action === "delete-visit" && domain && url) {
      await chrome.runtime.sendMessage({ type: "delete-history-visit", domain, url });
      await loadHistoryTree();
    }
  });
}

function switchTab(name) {
  activeSection = ui.tabPanels[name] ? name : "main";

  Object.entries(ui.tabPanels).forEach(([panelName, panel]) => {
    panel.classList.toggle("hidden", panelName !== activeSection);
  });

  ui.tabButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.tabTarget === activeSection);
  });
}

async function ensureBackendBaseUrl() {
  const values = await chrome.storage.local.get(STORAGE_KEYS.backendBaseUrl);
  if (!values[STORAGE_KEYS.backendBaseUrl]) {
    await chrome.storage.local.set({ [STORAGE_KEYS.backendBaseUrl]: DEFAULT_API_BASE_URL });
  }
}

async function getStored(keys) {
  return chrome.storage.local.get(keys);
}

async function getBackendBaseUrl() {
  const values = await getStored(STORAGE_KEYS.backendBaseUrl);
  return values[STORAGE_KEYS.backendBaseUrl] || DEFAULT_API_BASE_URL;
}

async function getSessionToken() {
  const values = await getStored(STORAGE_KEYS.sessionToken);
  return values[STORAGE_KEYS.sessionToken] || "";
}

async function getSessionUser() {
  const values = await getStored(STORAGE_KEYS.sessionUser);
  return values[STORAGE_KEYS.sessionUser] || null;
}

async function getPendingPairing() {
  const values = await getStored(STORAGE_KEYS.pendingPairing);
  return values[STORAGE_KEYS.pendingPairing] || null;
}

async function storeSession(token, user) {
  currentSessionUser = user || null;
  await chrome.storage.local.set({
    [STORAGE_KEYS.sessionToken]: token,
    [STORAGE_KEYS.sessionUser]: user,
  });
  await chrome.storage.local.remove(STORAGE_KEYS.pendingPairing);
}

async function storePendingPairing(pairing) {
  await chrome.storage.local.set({ [STORAGE_KEYS.pendingPairing]: pairing });
}

async function clearPendingPairing() {
  await chrome.storage.local.remove(STORAGE_KEYS.pendingPairing);
}

async function clearSessionStorage() {
  currentSessionUser = null;
  await chrome.storage.local.remove([
    STORAGE_KEYS.sessionToken,
    STORAGE_KEYS.sessionUser,
    STORAGE_KEYS.pendingPairing,
  ]);
  await chrome.runtime.sendMessage({ type: "clear-session" });
}

async function apiRequest(path, options = {}) {
  const backendBaseUrl = await getBackendBaseUrl();
  const token = await getSessionToken();
  const headers = new Headers(options.headers || {});
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return fetch(`${backendBaseUrl}${path}`, {
    ...options,
    headers,
  });
}

function renderAccountSummary(user, status) {
  ui.accountUsername.textContent = user?.username || "-";
  ui.accountEmail.textContent = user?.email || "-";
  ui.accountStatus.textContent = status;
}

function setBadgeTone(node, tone, text) {
  if (!node) return;
  node.classList.remove(
    "status-badge--neutral",
    "status-badge--connected",
    "status-badge--warning",
    "status-badge--danger",
    "status-badge--pending",
    "status-badge--safe",
  );
  node.classList.add(
    tone === "connected"
      ? "status-badge--connected"
      : tone === "warning"
        ? "status-badge--warning"
        : tone === "danger"
          ? "status-badge--danger"
          : tone === "pending"
            ? "status-badge--pending"
            : tone === "safe"
              ? "status-badge--safe"
              : "status-badge--neutral",
  );
  node.textContent = text;
}

function updateHeaderState() {
  if (!currentSessionUser) {
    setBadgeTone(ui.headerSessionBadge, "danger", "Account needed");
  } else {
    setBadgeTone(ui.headerSessionBadge, "connected", `Connected: ${currentSessionUser.username}`);
  }

  if (!activeScan) {
    setBadgeTone(ui.headerPageBadge, "neutral", "Waiting for a site");
    return;
  }

  if (activeScan.status === "pending") {
    setBadgeTone(ui.headerPageBadge, "pending", "Scan in progress");
    return;
  }

  if (activeScan.status === "error") {
    setBadgeTone(ui.headerPageBadge, "warning", "Scan failed");
    return;
  }

  if (activeScan.status === "disconnected") {
    setBadgeTone(ui.headerPageBadge, "danger", "Reconnect required");
    return;
  }

  if (activeScan.warningActive || activeScan.verdict === "malicious") {
    setBadgeTone(ui.headerPageBadge, "danger", `${String(activeScan.verdict || "risk").toUpperCase()} site`);
    return;
  }

  if (activeScan.verdict === "suspicious") {
    setBadgeTone(ui.headerPageBadge, "warning", "Review before trust");
    return;
  }

  if (activeScan.verdict === "safe") {
    setBadgeTone(ui.headerPageBadge, "safe", "Quick scan looks clean");
    return;
  }

  setBadgeTone(ui.headerPageBadge, "neutral", "Waiting for a site");
}

async function hydrateSession() {
  const storedUser = await getSessionUser();
  currentSessionUser = storedUser;
  if (!storedUser) {
    if (await resumePendingPairing()) {
      return;
    }
    renderDisconnectedState();
    return;
  }

  try {
    const response = await apiRequest("/api/extension/session");
    if (!response.ok) {
      await clearSessionStorage();
      if (await resumePendingPairing()) {
        return;
      }
      renderDisconnectedState("Your website session has expired. Reconnect the extension.");
      return;
    }

    const data = await response.json();
    currentSessionUser = data.user || storedUser;
    renderConnectedState(currentSessionUser);
    await loadChatProviders();
  } catch {
    if (await resumePendingPairing()) {
      return;
    }
    renderDisconnectedState("The SecureLens backend is unreachable right now.");
  }
}

function renderDisconnectedState(message) {
  ui.sessionHeadline.textContent = "Not connected";
  ui.sessionSubtle.textContent =
    message || "Connect the extension from your SecureLens website account.";
  renderAccountSummary(currentSessionUser, "Disconnected");
  ui.connectBtn.classList.remove("hidden");
  ui.disconnectBtn.classList.add("hidden");
  ui.scanCard.classList.add("hidden");
  ui.intelCard.classList.add("hidden");
  activeScan = null;
  hidePairing();
  renderProtectionPulse();
  renderScanTimeline();
  renderAssistantContext();
  setChatAvailability(false, "Connect your account and finish a scan to use the assistant.");
  updateHeaderState();
  switchTab("account");
}

function renderConnectedState(user) {
  ui.sessionHeadline.textContent = `Connected as ${user.username}`;
  ui.sessionSubtle.textContent = "Your extension is linked and ready to scan the active website.";
  renderAccountSummary(user, "Connected");
  ui.connectBtn.classList.add("hidden");
  ui.disconnectBtn.classList.remove("hidden");
  renderProtectionPulse();
  renderScanTimeline(activeScan);
  renderAssistantContext(activeScan);
  updateHeaderState();
}

function showPairing(message) {
  ui.pairingCard.classList.remove("hidden");
  ui.pairingStatus.textContent = message;
  renderAccountSummary(currentSessionUser, "Waiting for approval");
  setBadgeTone(ui.headerSessionBadge, "pending", "Approval required");
}

function hidePairing() {
  ui.pairingCard.classList.add("hidden");
}

function showMessage(message) {
  ui.messageCard.classList.remove("hidden");
  ui.messageText.textContent = message;
}

function hideMessage() {
  ui.messageCard.classList.add("hidden");
}

function clearChildren(node) {
  if (!node) return;
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function setConfidenceTone(tone) {
  ui.intelConfidence.classList.remove("confidence-pill--high", "confidence-pill--medium", "confidence-pill--low");
  ui.intelConfidence.classList.add(
    tone === "high" ? "confidence-pill--high" : tone === "medium" ? "confidence-pill--medium" : "confidence-pill--low",
  );
}

function renderProtectionPulse(scan = activeScan) {
  const accountLabel = currentSessionUser ? `Connected as ${currentSessionUser.username}` : "Disconnected";
  let pageLabel = scan?.canonical_domain || "No site";
  if (pageLabel === "No site" && activeTab?.url) {
    try {
      pageLabel = new URL(activeTab.url).hostname || "No site";
    } catch {
      pageLabel = "No site";
    }
  }
  let decisionLabel = "Waiting";
  let reportLabel = "Unavailable";
  let summary =
    currentSessionUser
      ? "SecureLens is ready. Open a website tab or refresh the current one to generate a quick verdict."
      : "Connect the extension to start scanning the active site and unlock the assistant.";

  if (scan?.status === "pending") {
    decisionLabel = "Scanning";
    summary = "The active tab is being analyzed. Verdict, signals, and the assistant will update as evidence arrives.";
  } else if (scan?.status === "completed") {
    decisionLabel = `${String(scan.verdict || "unknown").toUpperCase()} • ${scan.risk_score ?? 0}%`;
    reportLabel = scan.deep_scan_path ? "Ready" : "Not generated";
    summary = scan.warningActive
      ? "A warning page interrupted navigation because the current verdict is risky."
      : "The active site has a fresh quick verdict and a generated threat brief.";
  } else if (scan?.status === "error") {
    decisionLabel = "Scan error";
    summary = scan.error || "SecureLens could not analyze the current tab.";
  } else if (scan?.status === "disconnected") {
    decisionLabel = "Account needed";
    summary = scan.error || "Reconnect the extension to restart quick scanning.";
  }

  ui.pulseSummary.textContent = summary;
  ui.pulseAccount.textContent = accountLabel;
  ui.pulsePage.textContent = pageLabel;
  ui.pulseDecision.textContent = decisionLabel;
  ui.pulseReport.textContent = reportLabel;
}

function buildTimelineItem(type, title, meta) {
  return `
    <article class="timeline-item ${type ? `timeline-item--${type}` : ""}">
      <div class="timeline-item__dot"></div>
      <div class="timeline-item__copy">
        <div class="timeline-item__title">${escapeHtml(title)}</div>
        <div class="timeline-item__meta">${escapeHtml(meta)}</div>
      </div>
    </article>
  `;
}

function renderScanTimeline(scan = activeScan) {
  let items = [];

  items.push(
    buildTimelineItem(
      currentSessionUser ? "success" : "warning",
      currentSessionUser ? "Account connected" : "Website account required",
      currentSessionUser
        ? `Signed in as ${currentSessionUser.username}.`
        : "Pair the extension with your SecureLens website account before scanning sites.",
    ),
  );

  if (!scan) {
    items.push(
      buildTimelineItem(
        "",
        "No active site verdict",
        "Open a normal website tab and refresh to see the quick decision timeline here.",
      ),
    );
    ui.timelineList.innerHTML = items.join("");
    return;
  }

  if (scan.status === "pending") {
    items.push(
      buildTimelineItem(
        "",
        "Quick scan started",
        `SecureLens is collecting reputation, URL-shape, and passive exposure context for ${scan.currentUrl || scan.original_input || "the active site"}.`,
      ),
    );
    items.push(
      buildTimelineItem(
        "",
        "Threat brief pending",
        "The explanation layer and assistant will unlock automatically when the quick scan completes.",
      ),
    );
    ui.timelineList.innerHTML = items.join("");
    return;
  }

  if (scan.status === "error") {
    items.push(buildTimelineItem("warning", "Scan failed", scan.error || "Unable to scan the current tab."));
    ui.timelineList.innerHTML = items.join("");
    return;
  }

  if (scan.status === "disconnected") {
    items.push(
      buildTimelineItem("warning", "Session expired", scan.error || "Reconnect the extension to continue scanning."),
    );
    ui.timelineList.innerHTML = items.join("");
    return;
  }

  const verdict = String(scan.verdict || "unknown").toUpperCase();
  items.push(
    buildTimelineItem(
      scan.warningActive || scan.verdict === "malicious" ? "warning" : "success",
      `Quick verdict: ${verdict}`,
      `${scan.risk_score ?? 0}% risk score with ${scan.virus_total?.detection_ratio || `${scan.virus_total?.total_engines ?? 0} engine(s)`}.`,
    ),
  );
  items.push(
    buildTimelineItem(
      scan.warningActive ? "warning" : "",
      scan.warningActive ? "Warning page opened" : "Threat brief generated",
      scan.warningActive
        ? "SecureLens interrupted navigation because the current verdict is risky."
        : "The site remained open and the local threat brief is ready for review.",
    ),
  );
  items.push(
    buildTimelineItem(
      scan.deep_scan_path ? "success" : "",
      scan.deep_scan_path ? "AI report available" : "AI report unavailable",
      scan.deep_scan_path
        ? "A deeper report can be opened directly from the overview or warning page."
        : "No deep report path is currently attached to this scan.",
    ),
  );
  items.push(
    buildTimelineItem(
      scan.status === "completed" ? "success" : "",
      "Assistant ready",
      "Use the Assistant tab to ask for plain-language risks, safer next steps, or an explanation of the verdict.",
    ),
  );
  ui.timelineList.innerHTML = items.join("");
}

function renderAssistantContext(scan = activeScan) {
  if (!scan || scan.status !== "completed") {
    ui.assistantHeadline.textContent = "Ask SecureLens AI";
    ui.assistantSummary.textContent = "The assistant becomes much more useful after a completed quick scan.";
    setBadgeTone(ui.assistantVerdictBadge, "neutral", "No scan yet");
    ui.assistantFactGrid.innerHTML =
      '<div class="assistant-empty">Run a scan to populate the facts the assistant will use for follow-up questions.</div>';
    return;
  }

  const intel = window.SecureLensIntel?.analyzeScan(scan);
  const verdictTone =
    scan.verdict === "malicious"
      ? "danger"
      : scan.verdict === "suspicious"
        ? "warning"
        : scan.verdict === "safe"
          ? "safe"
          : "neutral";

  ui.assistantHeadline.textContent = intel?.headline || `Ask about ${scan.canonical_domain || "this site"}`;
  ui.assistantSummary.textContent =
    intel?.summary || "Ask for a simpler explanation, the biggest risks, or the safest next step.";
  setBadgeTone(
    ui.assistantVerdictBadge,
    verdictTone,
    `${String(scan.verdict || "unknown").toUpperCase()} • ${scan.risk_score ?? 0}%`,
  );

  const facts = intel?.facts?.slice(0, 4) || [
    { label: "Domain", value: scan.canonical_domain || "-" },
    { label: "Risk", value: `${scan.risk_score ?? 0}%` },
  ];

  ui.assistantFactGrid.innerHTML = facts
    .map(
      (fact) => `
        <div class="assistant-fact">
          <span class="assistant-fact__label">${escapeHtml(fact.label)}</span>
          <span class="assistant-fact__value">${escapeHtml(fact.value)}</span>
        </div>
      `,
    )
    .join("");
}

function setChatAvailability(enabled, message) {
  const hasProviderOptions = ui.providerSelect.options.length > 0;
  const providerReady = Boolean(selectedProvider) && hasProviderOptions && ui.providerSelect.value !== "";
  const providerUnavailable = enabled && hasProviderOptions && !providerReady;
  const effectiveEnabled = enabled && providerReady;
  const availabilityMessage = providerUnavailable ? "No AI providers are currently available." : message;

  ui.chatCard.classList.toggle("is-disabled", !effectiveEnabled);
  ui.providerSelect.disabled = !effectiveEnabled || !hasProviderOptions;
  ui.chatInput.disabled = !effectiveEnabled;
  ui.chatSendBtn.disabled = !effectiveEnabled;
  ui.promptButtons.forEach((button) => {
    button.disabled = !effectiveEnabled;
  });
  ui.chatAvailabilityText.textContent = availabilityMessage;
  ui.chatEmpty.textContent = availabilityMessage;
  if (!effectiveEnabled) {
    renderChatHistory([]);
  }
}

function renderIntelPlaceholder(title, summary, actionText) {
  ui.intelCard.classList.remove("hidden");
  ui.intelHeadline.textContent = title;
  ui.intelConfidence.textContent = "Baseline confidence";
  setConfidenceTone("low");
  ui.intelSummary.textContent = summary;

  clearChildren(ui.signalList);
  const signalEmpty = document.createElement("div");
  signalEmpty.className = "intel-empty";
  signalEmpty.textContent = "Signal details will populate as soon as SecureLens finishes collecting evidence.";
  ui.signalList.appendChild(signalEmpty);

  clearChildren(ui.actionList);
  const actionEmpty = document.createElement("div");
  actionEmpty.className = "intel-empty";
  actionEmpty.textContent = actionText;
  ui.actionList.appendChild(actionEmpty);

  clearChildren(ui.factGrid);
  [
    { label: "Status", value: "Collecting evidence" },
    { label: "Scope", value: activeTab?.url || "Active tab" },
  ].forEach((fact) => {
    const card = document.createElement("div");
    card.className = "fact-card";

    const label = document.createElement("span");
    label.className = "fact-card__label";
    label.textContent = fact.label;

    const value = document.createElement("span");
    value.className = "fact-card__value";
    value.textContent = fact.value;

    card.append(label, value);
    ui.factGrid.appendChild(card);
  });

  ui.portsSummary.textContent = "Port enrichment runs in the background when telemetry is available.";
}

function renderThreatIntelligence(scan) {
  const intel = window.SecureLensIntel?.analyzeScan(scan);
  if (!intel) {
    renderIntelPlaceholder(
      "Threat reasoning is temporarily unavailable",
      "The scan finished, but the local explanation layer could not be generated.",
      "You can still open the full AI report for a deeper decision.",
    );
    return;
  }

  ui.intelCard.classList.remove("hidden");
  ui.intelHeadline.textContent = intel.headline;
  ui.intelSummary.textContent = intel.summary;
  ui.intelConfidence.textContent = intel.confidence.label;
  setConfidenceTone(intel.confidence.tone);

  clearChildren(ui.signalList);
  intel.signals.forEach((signal) => {
    const item = document.createElement("article");
    item.className = `signal-item signal-item--${signal.severity}`;

    const title = document.createElement("span");
    title.className = "signal-item__title";
    title.textContent = signal.title;

    const copy = document.createElement("span");
    copy.className = "signal-item__copy";
    copy.textContent = signal.detail;

    item.append(title, copy);
    ui.signalList.appendChild(item);
  });

  clearChildren(ui.actionList);
  intel.actions.forEach((actionText) => {
    const item = document.createElement("article");
    item.className = "action-item";

    const title = document.createElement("span");
    title.className = "action-item__title";
    title.textContent = "Recommended action";

    const copy = document.createElement("span");
    copy.className = "action-item__copy";
    copy.textContent = actionText;

    item.append(title, copy);
    ui.actionList.appendChild(item);
  });

  clearChildren(ui.factGrid);
  intel.facts.forEach((fact) => {
    const card = document.createElement("div");
    card.className = "fact-card";

    const label = document.createElement("span");
    label.className = "fact-card__label";
    label.textContent = fact.label;

    const value = document.createElement("span");
    value.className = "fact-card__value";
    value.textContent = fact.value;

    card.append(label, value);
    ui.factGrid.appendChild(card);
  });

  ui.portsSummary.textContent = scan.ports_refreshing
    ? `Ports seen: ${intel.portsSummary}. Background enrichment is still refreshing.`
    : `Ports seen: ${intel.portsSummary}.`;
}

async function startPairing() {
  hideMessage();
  showPairing("Creating a secure website approval request...");
  ui.connectBtn.disabled = true;
  switchTab("account");

  try {
    const backendBaseUrl = await getBackendBaseUrl();
    const response = await fetch(`${backendBaseUrl}/api/extension/pairings`, { method: "POST" });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Unable to create a pairing request.");
    }

    await storePendingPairing({
      pairingId: data.pairing_id,
      pollToken: data.poll_token,
      createdAtMs: Date.now(),
    });
    showPairing("Approve the request in the website tab that just opened.");
    await chrome.tabs.create({ url: data.approval_url });
    await pollPairing(data.pairing_id, data.poll_token);
  } catch (error) {
    showPairing(error.message || "Pairing failed.");
  } finally {
    ui.connectBtn.disabled = false;
  }
}

async function pollPairing(pairingId, pollToken) {
  const backendBaseUrl = await getBackendBaseUrl();
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const response = await fetch(
      `${backendBaseUrl}/api/extension/pairings/${pairingId}?poll_token=${encodeURIComponent(pollToken)}`,
    );
    const data = await response.json();
    if (response.ok && data.status === "approved" && data.token) {
      await storeSession(data.token, data.user);
      hidePairing();
      renderConnectedState(data.user);
      await loadChatProviders();
      switchTab("main");
      await forceQuickScan(true);
      return;
    }

    if (!response.ok || data.status === "expired" || data.status === "completed") {
      await clearPendingPairing();
      showPairing("This pairing request can no longer be used. Start a new connection from the popup.");
      return;
    }

    showPairing("Waiting for website approval...");
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  await clearPendingPairing();
  showPairing("Approval timed out. Start a new connection from the popup.");
}

async function resumePendingPairing() {
  const pairing = await getPendingPairing();
  if (!pairing?.pairingId || !pairing?.pollToken) {
    return false;
  }

  showPairing("Checking the approval you already started...");
  switchTab("account");
  await pollPairing(pairing.pairingId, pairing.pollToken);
  return Boolean(await getSessionToken());
}

async function disconnectExtension() {
  try {
    await apiRequest("/api/extension/logout", { method: "POST" });
  } catch {
    // Best-effort revoke.
  }
  await clearSessionStorage();
  renderDisconnectedState("The extension has been disconnected.");
  switchTab("account");
}

async function loadActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab || null;

  if (!activeTab?.url || !/^https?:/i.test(activeTab.url)) {
    if (activeTab?.id) {
      const state = await chrome.runtime.sendMessage({
        type: "get-scan-state",
        tabId: activeTab.id,
      });
      if (state) {
        renderScanState(state);
        showMessage("This tab is currently showing a SecureLens warning page.");
        return;
      }
    }
    activeScan = null;
    ui.scanCard.classList.add("hidden");
    ui.intelCard.classList.add("hidden");
    renderProtectionPulse();
    renderScanTimeline();
    renderAssistantContext();
    updateHeaderState();
    setChatAvailability(false, "Open a normal website tab to unlock chat about a real scan.");
    showMessage("Open a normal website tab to scan it.");
    return;
  }

  await forceQuickScan(false);
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text || "";
  return div.innerHTML;
}

function formatTimestamp(timestampMs) {
  if (!timestampMs) return "Unknown time";
  return new Date(timestampMs).toLocaleString();
}

function buildStatusChip(verdict) {
  const normalized = (verdict || "suspicious").toLowerCase();
  return `<span class="status-chip status-chip--${normalized}">${escapeHtml(normalized.toUpperCase())}</span>`;
}

function buildGroupRootUrl(group) {
  const firstVisit = (group.visits || [])[0];
  if (firstVisit?.url) {
    try {
      const parsed = new URL(firstVisit.url);
      return `${parsed.protocol}//${parsed.hostname}/`;
    } catch {
      // Fall through to canonical fallback.
    }
  }
  return `https://${group.canonicalDomain}/`;
}

function buildVisitPath(url, canonicalDomain) {
  if (!url) return "/";
  try {
    const parsed = new URL(url);
    const path = `${parsed.pathname || "/"}${parsed.search || ""}${parsed.hash || ""}`;
    if (parsed.hostname === canonicalDomain && path) {
      return path;
    }
    return `${parsed.hostname}${path}`;
  } catch {
    return url;
  }
}

function filterHistoryGroup(group, query) {
  if (!query) return group;

  const haystack = `${group.canonicalDomain} ${group.verdict || ""} ${buildGroupRootUrl(group)}`.toLowerCase();
  if (haystack.includes(query)) {
    return group;
  }

  const visits = (group.visits || []).filter((visit) => {
    const visitHaystack = `${visit.url || ""} ${visit.verdict || ""} ${visit.label || ""}`.toLowerCase();
    return visitHaystack.includes(query);
  });

  if (!visits.length) {
    return null;
  }

  return { ...group, visits };
}

function renderHistoryMetrics(history) {
  const visits = history.reduce((count, group) => count + (group.visits || []).length, 0);
  const riskyGroups = history.filter((group) => group.verdict === "malicious" || group.verdict === "suspicious").length;
  ui.historyDomainCount.textContent = String(history.length);
  ui.historyRiskCount.textContent = String(riskyGroups);
  ui.historyVisitCount.textContent = String(visits);
}

async function loadHistoryTree() {
  try {
    const history = await chrome.runtime.sendMessage({ type: "get-history" });
    historySnapshot = history || [];
    renderHistoryTree(historySnapshot);
  } catch {
    historySnapshot = [];
    renderHistoryMetrics([]);
    ui.historyTree.innerHTML = '<div class="history-empty">Unable to load local extension history right now.</div>';
  }
}

function renderHistoryTree(history) {
  const filteredHistory = (history || [])
    .map((group) => filterHistoryGroup(group, historySearchQuery))
    .filter(Boolean);

  renderHistoryMetrics(filteredHistory);

  if (!filteredHistory.length) {
    ui.historyTree.innerHTML = historySearchQuery
      ? '<div class="history-empty">No saved domains or URLs match the current search.</div>'
      : '<div class="history-empty">No local extension history yet.</div>';
    return;
  }

  ui.historyTree.innerHTML = filteredHistory
    .map((group) => {
      const groupReportButton = group.deepScanPath
        ? `<button class="icon-btn icon-btn--accent" data-history-action="report" data-report-path="${escapeHtml(group.deepScanPath)}" title="Open report">AI</button>`
        : "";

      const visits = (group.visits || [])
        .map((visit) => {
          const visitReportButton = visit.deepScanPath
            ? `<button class="icon-btn icon-btn--accent" data-history-action="report" data-report-path="${escapeHtml(visit.deepScanPath)}" title="Open report">AI</button>`
            : "";

          return `
            <div class="history-visit">
              <div class="history-visit-copy">
                <div class="history-visit-path">${escapeHtml(buildVisitPath(visit.url, group.canonicalDomain))}</div>
                <div class="history-visit-url">${escapeHtml(visit.url)}</div>
                <div class="history-visit-meta">
                  ${buildStatusChip(visit.verdict)}
                  <span>${escapeHtml(String(visit.riskScore ?? 0))}% risk</span>
                  <span>Saved ${escapeHtml(formatTimestamp(visit.updatedAtMs))}</span>
                </div>
              </div>
              <div class="history-actions">
                ${visitReportButton}
                <button class="icon-btn" data-history-action="open" data-domain="${escapeHtml(group.canonicalDomain)}" data-url="${escapeHtml(visit.url)}" title="Open URL">Open</button>
                <button class="icon-btn icon-btn--danger" data-history-action="delete-visit" data-domain="${escapeHtml(group.canonicalDomain)}" data-url="${escapeHtml(visit.url)}" title="Delete URL">Delete</button>
              </div>
            </div>
          `;
        })
        .join("");

      return `
        <details class="history-group">
          <summary class="history-summary">
            <div class="history-summary-main">
              <span class="history-caret">&gt;</span>
              <div class="history-summary-copy">
                <div class="history-domain">${escapeHtml(group.canonicalDomain)}</div>
                <div class="history-root-url">${escapeHtml(buildGroupRootUrl(group))}</div>
                <div class="history-meta">
                  ${buildStatusChip(group.verdict)}
                  <span>${escapeHtml(String(group.riskScore ?? 0))}% risk</span>
                  <span>${escapeHtml(String((group.visits || []).length))} saved URL(s)</span>
                </div>
              </div>
            </div>
            <div class="history-actions">
              ${groupReportButton}
              <button class="icon-btn" data-history-action="open" data-domain="${escapeHtml(group.canonicalDomain)}" data-url="${escapeHtml(buildGroupRootUrl(group))}" title="Open root URL">Open</button>
              <button class="icon-btn icon-btn--danger" data-history-action="delete-domain" data-domain="${escapeHtml(group.canonicalDomain)}" title="Delete domain history">Delete</button>
            </div>
          </summary>
          <div class="history-children">${visits}</div>
        </details>
      `;
    })
    .join("");
}

async function forceQuickScan(forceMessage) {
  hideMessage();
  if (!activeTab?.url || !/^https?:/i.test(activeTab.url)) {
    showMessage("Open a normal website tab to scan it.");
    return;
  }

  const token = await getSessionToken();
  if (!token) {
    renderDisconnectedState("Connect the extension from your website account first.");
    return;
  }

  if (forceMessage) {
    showMessage("Refreshing quick scan...");
  }

  await chrome.runtime.sendMessage({
    type: "force-scan",
    tabId: activeTab.id,
    url: activeTab.url,
  });

  setTimeout(async () => {
    const state = await chrome.runtime.sendMessage({
      type: "get-scan-state",
      tabId: activeTab.id,
    });
    renderScanState(state);
    await loadHistoryTree();
    if (!state?.warningActive) {
      hideMessage();
    }
  }, 500);
}

function renderScanState(scan) {
  if (pendingPollTimer) {
    clearTimeout(pendingPollTimer);
    pendingPollTimer = null;
  }

  if (!scan) {
    activeScan = null;
    ui.scanCard.classList.add("hidden");
    ui.intelCard.classList.add("hidden");
    renderProtectionPulse();
    renderScanTimeline();
    renderAssistantContext();
    setChatAvailability(false, "Finish a scan to ask for an explanation, risks, or next steps.");
    updateHeaderState();
    return;
  }

  if (scan.status === "disconnected") {
    renderDisconnectedState(scan.error);
    return;
  }

  if (scan.status === "error") {
    activeScan = scan;
    ui.scanCard.classList.add("hidden");
    ui.intelCard.classList.add("hidden");
    renderProtectionPulse(scan);
    renderScanTimeline(scan);
    renderAssistantContext(scan);
    setChatAvailability(false, scan.error || "The assistant is unavailable until the current tab can be scanned.");
    showMessage(scan.error || "Unable to scan the current tab.");
    updateHeaderState();
    return;
  }

  ui.scanCard.classList.remove("hidden");
  ui.domainValue.textContent = scan.canonical_domain || "-";
  ui.scanUrlValue.textContent = scan.original_input || scan.currentUrl || "-";
  ui.scanDetectionRatio.textContent = scan.virus_total?.detection_ratio
    ? `${scan.virus_total.detection_ratio} engines`
    : `${scan.virus_total?.total_engines ?? 0} engines`;
  ui.openReportBtn.classList.toggle("hidden", !scan.deep_scan_path);
  ui.verdictBox.classList.remove("verdict--safe", "verdict--suspicious", "verdict--malicious");

  if (scan.status === "pending") {
    activeScan = scan;
    ui.scanStatePill.textContent = "Scanning";
    ui.verdictLabel.textContent = "Quick scan in progress";
    ui.verdictHelp.textContent = "SecureLens is collecting reputation, URL-shape, and passive exposure context.";
    ui.verdictScore.textContent = "...";
    ui.vtMalicious.textContent = 0;
    ui.vtSuspicious.textContent = 0;
    ui.vtHarmless.textContent = 0;
    ui.vtTotal.textContent = scan.virus_total?.total_engines ?? 0;
    renderIntelPlaceholder(
      "Building a threat brief",
      "The popup keeps the interface readable, but waits for evidence before making claims about the active site.",
      "Wait for the quick scan to finish or refresh if the page just changed.",
    );
    renderProtectionPulse(scan);
    renderScanTimeline(scan);
    renderAssistantContext(scan);
    setChatAvailability(false, "The assistant unlocks when the quick scan finishes.");
    updateHeaderState();
    pendingPollTimer = setTimeout(() => pollActiveScan(scan.scan_id), 1800);
    return;
  }

  activeScan = scan;
  ui.scanStatePill.textContent = scan.warningActive ? "Warning shown" : "Ready";
  ui.verdictLabel.textContent = (scan.verdict || "unknown").toUpperCase();
  ui.verdictScore.textContent = `${scan.risk_score ?? 0}%`;
  ui.verdictBox.classList.add(`verdict--${scan.verdict || "suspicious"}`);
  ui.verdictHelp.textContent = scan.warningActive
    ? "SecureLens interrupted navigation because the current verdict is risky."
    : "Quick verdict based on backend telemetry plus local URL-context analysis.";
  ui.vtMalicious.textContent = scan.virus_total?.malicious_count ?? 0;
  ui.vtSuspicious.textContent = scan.virus_total?.suspicious_count ?? 0;
  ui.vtHarmless.textContent = scan.virus_total?.harmless_count ?? 0;
  ui.vtTotal.textContent = scan.virus_total?.total_engines ?? 0;
  renderThreatIntelligence(scan);
  renderProtectionPulse(scan);
  renderScanTimeline(scan);
  renderAssistantContext(scan);
  setChatAvailability(true, "Ask for a simpler explanation, the biggest risks, or the safest next step.");
  updateHeaderState();

  if (scan.warningActive && (scan.verdict === "malicious" || scan.verdict === "suspicious")) {
    showMessage("SecureLens opened a warning page for this tab because the verdict is risky.");
  }

  loadChatHistory();
}

async function pollActiveScan(scanId) {
  try {
    const response = await apiRequest(`/api/extension/scans/${scanId}`);
    if (!response.ok) return;
    const data = await response.json();
    renderScanState(data);
    await loadHistoryTree();
  } catch {
    // Popup can recover with manual refresh.
  }
}

async function openReportPath(reportPath) {
  if (!reportPath) return;
  const backendBaseUrl = await getBackendBaseUrl();
  await chrome.tabs.create({ url: `${backendBaseUrl}${reportPath}` });
}

async function openFullReport() {
  if (!activeScan?.deep_scan_path) return;
  await openReportPath(activeScan.deep_scan_path);
}

async function loadChatProviders() {
  try {
    const response = await apiRequest("/api/extension/chat/providers");
    if (!response.ok) {
      throw new Error("providers-unavailable");
    }
    const data = await response.json();
    const providers = data.providers || [];
    const firstAvailable = providers.find((provider) => provider.available);
    selectedProvider = data.default_provider || firstAvailable?.id || "";
    ui.providerSelect.innerHTML = "";

    if (!providers.length) {
      const option = document.createElement("option");
      option.textContent = "No providers available";
      option.value = "";
      ui.providerSelect.appendChild(option);
      ui.providerSelect.disabled = true;
      return;
    }

    providers.forEach((provider) => {
      const option = document.createElement("option");
      option.value = provider.id;
      option.textContent = provider.available
        ? `${provider.display_name}${provider.model ? ` • ${provider.model}` : ""}`
        : `${provider.display_name} (Unavailable)`;
      option.disabled = !provider.available;
      option.selected = provider.id === selectedProvider;
      ui.providerSelect.appendChild(option);
    });
  } catch {
    selectedProvider = "";
    ui.providerSelect.innerHTML = '<option value="">Providers unavailable</option>';
    ui.providerSelect.disabled = true;
  }
}

function appendChatBubble(role, text) {
  ui.chatEmpty.classList.add("hidden");
  const bubble = document.createElement("div");
  bubble.className = `chat-bubble chat-bubble--${role}`;
  bubble.textContent = text;
  ui.chatLog.appendChild(bubble);
  ui.chatLog.scrollTop = ui.chatLog.scrollHeight;
}

function renderChatHistory(history) {
  ui.chatLog.innerHTML = "";
  if (!history?.length) {
    ui.chatLog.appendChild(ui.chatEmpty);
    ui.chatEmpty.classList.remove("hidden");
    return;
  }

  history.forEach((item) => appendChatBubble(item.role === "user" ? "user" : "assistant", item.content));
}

async function loadChatHistory() {
  if (!activeScan?.scan_id || !selectedProvider) return;
  try {
    const response = await apiRequest(
      `/api/extension/chat/history/${activeScan.scan_id}/${encodeURIComponent(selectedProvider)}`,
    );
    if (!response.ok) return;
    const history = await response.json();
    renderChatHistory(history);
  } catch {
    // Leave current chat state alone.
  }
}

async function sendChatMessage(event) {
  event.preventDefault();
  const message = ui.chatInput.value.trim();
  if (!message || !activeScan?.scan_id || !selectedProvider) return;

  ui.chatInput.value = "";
  appendChatBubble("user", message);

  try {
    const response = await apiRequest("/api/extension/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: activeScan.scan_id,
        message,
        provider: selectedProvider,
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      appendChatBubble("assistant", data.detail || "The AI assistant could not answer right now.");
      return;
    }
    appendChatBubble("assistant", data.response || "No response received.");
  } catch {
    appendChatBubble("assistant", "The SecureLens backend is unreachable right now.");
  }
}
