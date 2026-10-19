(function () {
  const LOW_TRUST_TLDS = new Set([
    "xyz",
    "top",
    "click",
    "zip",
    "mov",
    "work",
    "live",
    "cam",
    "rest",
    "online",
    "site",
  ]);

  const AUTH_TERMS = [
    "login",
    "signin",
    "verify",
    "password",
    "passcode",
    "auth",
    "account",
    "recovery",
    "confirm",
    "security-check",
  ];

  const FINANCIAL_TERMS = [
    "bank",
    "paypal",
    "wallet",
    "invoice",
    "payment",
    "billing",
    "card",
    "checkout",
    "crypto",
  ];

  const URGENCY_TERMS = [
    "urgent",
    "alert",
    "suspend",
    "locked",
    "secure",
    "review",
    "action",
    "expired",
    "update",
    "warning",
  ];

  const DOWNLOAD_TERMS = [
    "download",
    "setup",
    "installer",
    "plugin",
    "extension",
    "apk",
    "exe",
    "update",
  ];

  const BRANDS = [
    "paypal",
    "google",
    "facebook",
    "microsoft",
    "apple",
    "amazon",
    "instagram",
    "whatsapp",
    "discord",
    "netflix",
    "steam",
    "telegram",
    "dropbox",
    "chase",
  ];

  const LOOKALIKE_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
  };

  function tryParseUrl(rawUrl) {
    if (!rawUrl) return null;
    try {
      return new URL(rawUrl);
    } catch {
      return null;
    }
  }

  function normalizeVerdict(verdict) {
    const value = String(verdict || "").toLowerCase();
    if (value === "malicious" || value === "suspicious" || value === "safe") {
      return value;
    }
    return "suspicious";
  }

  function normalizePorts(ports) {
    return Array.isArray(ports)
      ? ports
          .map((port) => Number(port))
          .filter((port) => Number.isFinite(port) && port > 0)
          .sort((left, right) => left - right)
      : [];
  }

  function dedupeById(items) {
    const seen = new Set();
    return items.filter((item) => {
      if (!item?.id || seen.has(item.id)) {
        return false;
      }
      seen.add(item.id);
      return true;
    });
  }

  function containsAny(text, terms) {
    const haystack = String(text || "").toLowerCase();
    return terms.some((term) => haystack.includes(term));
  }

  function isIpHostname(hostname) {
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname || "");
  }

  function normalizeLookalike(label) {
    return String(label || "")
      .toLowerCase()
      .split("")
      .map((char) => LOOKALIKE_MAP[char] || char)
      .join("");
  }

  function levenshtein(left, right) {
    if (left === right) return 0;
    if (!left) return right.length;
    if (!right) return left.length;

    const rows = Array.from({ length: left.length + 1 }, (_, index) => [index]);
    for (let column = 0; column <= right.length; column += 1) {
      rows[0][column] = column;
    }

    for (let row = 1; row <= left.length; row += 1) {
      for (let column = 1; column <= right.length; column += 1) {
        const cost = left[row - 1] === right[column - 1] ? 0 : 1;
        rows[row][column] = Math.min(
          rows[row - 1][column] + 1,
          rows[row][column - 1] + 1,
          rows[row - 1][column - 1] + cost,
        );
      }
    }

    return rows[left.length][right.length];
  }

  function findBrandImpersonation(hostname) {
    const labels = String(hostname || "")
      .toLowerCase()
      .split(".")
      .filter((label) => label && label !== "www");

    for (const label of labels) {
      const normalized = normalizeLookalike(label);
      for (const brand of BRANDS) {
        if (label === brand) continue;
        if (normalized === brand && label !== brand) {
          return brand;
        }
        if (
          Math.abs(normalized.length - brand.length) <= 1 &&
          normalized.length >= 5 &&
          levenshtein(normalized, brand) === 1
        ) {
          return brand;
        }
      }
    }

    return "";
  }

  function scoreBand(riskScore) {
    if (riskScore >= 85) return "Critical";
    if (riskScore >= 60) return "High";
    if (riskScore >= 30) return "Moderate";
    return "Low";
  }

  function buildConfidenceLabel(verdict, riskScore, vt, signals) {
    if (verdict === "malicious" || Number(vt.malicious_count || 0) >= 2 || riskScore >= 80) {
      return { label: "High confidence", tone: "high" };
    }
    if (verdict === "suspicious" || Number(vt.suspicious_count || 0) >= 2 || signals.length >= 3) {
      return { label: "Medium confidence", tone: "medium" };
    }
    return { label: "Baseline confidence", tone: "low" };
  }

  function summarizePorts(ports) {
    if (!ports.length) return "No recent port telemetry yet";
    if (ports.length <= 4) return ports.join(", ");
    return `${ports.slice(0, 4).join(", ")} +${ports.length - 4} more`;
  }

  function buildHeadline(verdict, riskScore) {
    if (verdict === "malicious") {
      return "Multiple signs point to an active threat";
    }
    if (verdict === "suspicious") {
      return riskScore >= 60 ? "This site needs careful review before trust" : "This site deserves a second look";
    }
    return "The quick scan looks clean so far";
  }

  function buildSummary(verdict, riskScore, signals, vt) {
    const topSignals = signals
      .filter((signal) => signal.severity !== "low")
      .slice(0, 2)
      .map((signal) => signal.title.toLowerCase());

    if (verdict === "malicious") {
      return topSignals.length
        ? `SecureLens saw malicious evidence and elevated indicators such as ${topSignals.join(" and ")}. Treat the page as unsafe until a deeper review proves otherwise.`
        : `SecureLens saw malicious evidence across the quick scan and this page should be treated as unsafe.`;
    }

    if (verdict === "suspicious") {
      if (Number(vt.suspicious_count || 0) > 0 || topSignals.length) {
        return `The quick scan is not clean. Suspicious evidence plus ${topSignals.join(" and ") || "uncertain reputation signals"} mean you should verify the target carefully before interacting with it.`;
      }
      return `The site is not confirmed malicious, but the current signal quality is weak enough that trust would be premature.`;
    }

    if (riskScore >= 25 || topSignals.length) {
      return `The scan came back mostly clean, but SecureLens still noticed ${topSignals.join(" and ") || "a few weak indicators"}. Stay alert for fake prompts, credential requests, or unexpected downloads.`;
    }

    return "No strong threat indicators were found in the quick scan. Continue normally, but keep standard caution for forms, downloads, and permission prompts.";
  }

  function buildActions(verdict, flags) {
    const actions = [];

    if (verdict === "malicious") {
      actions.push("Do not enter credentials, payment details, or one-time codes on this page.");
      actions.push("Close the tab and reopen the real service from a trusted bookmark or manually typed domain.");
    } else if (verdict === "suspicious") {
      actions.push("Pause before signing in or downloading anything until the full report confirms the site.");
    } else {
      actions.push("Proceed carefully and stop if the page asks for unusual credentials, downloads, or browser permissions.");
    }

    if (flags.brandImpersonation) {
      actions.push("Compare the hostname letter by letter with the official brand domain before trusting it.");
    }
    if (flags.financialTerms) {
      actions.push("Verify payment or banking pages through a known-good bookmark instead of following the current link.");
    }
    if (flags.insecureHttp) {
      actions.push("Avoid submitting sensitive information over plain HTTP because the traffic can be intercepted.");
    }
    if (flags.downloadLure) {
      actions.push("Do not run installers, browser extensions, or update packages offered by this page unless you independently verify the source.");
    }
    if (flags.unusualPorts) {
      actions.push("Treat exposed non-standard ports as extra attack surface and confirm they are expected for this service.");
    }

    actions.push("Open the full AI report if you need deeper evidence before making a decision.");

    return Array.from(new Set(actions)).slice(0, 4);
  }

  function buildSignals(data) {
    const parsedUrl = tryParseUrl(data.url);
    const hostname = String(data.canonicalDomain || parsedUrl?.hostname || "").toLowerCase();
    const pathname = `${parsedUrl?.pathname || "/"}${parsedUrl?.search || ""}`.toLowerCase();
    const urlText = `${hostname}${pathname}`;
    const vt = data.virusTotal;
    const ports = data.openPorts;
    const brand = findBrandImpersonation(hostname);
    const authTermsHit = containsAny(urlText, AUTH_TERMS);
    const financialTermsHit = containsAny(urlText, FINANCIAL_TERMS);
    const urgencyTermsHit = containsAny(urlText, URGENCY_TERMS);
    const downloadTermsHit = containsAny(urlText, DOWNLOAD_TERMS);
    const elevatedRisk =
      Number(vt.malicious_count || 0) > 0 ||
      Number(vt.suspicious_count || 0) > 0 ||
      Number(data.riskScore || 0) >= 40 ||
      data.verdict === "malicious" ||
      data.verdict === "suspicious";
    const signals = [];

    if (Number(vt.malicious_count || 0) > 0) {
      signals.push({
        id: "vt-malicious",
        severity: "high",
        title: "Malicious engine detections",
        detail: `${vt.malicious_count} engine(s) classified the target as malicious in the quick scan.`,
      });
    } else if (Number(vt.suspicious_count || 0) > 0) {
      signals.push({
        id: "vt-suspicious",
        severity: "medium",
        title: "Suspicious reputation evidence",
        detail: `${vt.suspicious_count} engine(s) marked the target as suspicious, which means trust should be withheld until a deeper review is complete.`,
      });
    }

    if (brand) {
      signals.push({
        id: "brand-impersonation",
        severity: "high",
        title: "Possible brand impersonation",
        detail: `The hostname resembles ${brand} using look-alike characters or near-match spelling, a common phishing technique.`,
      });
    }

    if (parsedUrl?.hostname?.startsWith("xn--")) {
      signals.push({
        id: "punycode",
        severity: "medium",
        title: "Encoded internationalized hostname",
        detail: "The hostname uses punycode encoding, which sometimes appears in homograph attacks that imitate trusted domains.",
      });
    }

    const tld = hostname.split(".").pop() || "";
    if (LOW_TRUST_TLDS.has(tld)) {
      signals.push({
        id: "tld",
        severity: elevatedRisk ? "medium" : "low",
        title: "Low-trust top-level domain",
        detail: `The domain ends in .${tld}, a suffix often seen in disposable or abuse-heavy campaigns.`,
      });
    }

    if (authTermsHit) {
      signals.push({
        id: "auth-lure",
        severity: elevatedRisk ? "medium" : "low",
        title: "Credential capture wording",
        detail: "The URL contains login or account-recovery language that is frequently used in phishing lures.",
      });
    }

    if (financialTermsHit) {
      signals.push({
        id: "financial-lure",
        severity: brand || elevatedRisk ? "high" : "medium",
        title: "Financial targeting pattern",
        detail: "The URL references payment or banking terms, which raises the cost of a mistaken click and often appears in fraud campaigns.",
      });
    }

    if (urgencyTermsHit && (authTermsHit || financialTermsHit || elevatedRisk)) {
      signals.push({
        id: "urgency",
        severity: "medium",
        title: "Urgency or pressure language",
        detail: "Security, warning, or urgency terms in the URL can be used to rush the user into acting without verification.",
      });
    }

    if (downloadTermsHit) {
      signals.push({
        id: "download-lure",
        severity: elevatedRisk ? "medium" : "low",
        title: "Download or update lure",
        detail: "The URL suggests an installer, extension, or urgent update flow, which is a common malware-delivery pattern.",
      });
    }

    if (parsedUrl && parsedUrl.protocol === "http:") {
      signals.push({
        id: "http",
        severity: "medium",
        title: "No HTTPS protection",
        detail: "The page is using plain HTTP, so traffic can be altered or intercepted in transit.",
      });
    }

    if (isIpHostname(hostname)) {
      signals.push({
        id: "ip-host",
        severity: "medium",
        title: "Direct IP destination",
        detail: "The site is being served from a raw IP address instead of a domain name, which is less typical for trusted public services.",
      });
    }

    const unusualPorts = ports.filter((port) => ![80, 443].includes(port));
    if (unusualPorts.length) {
      signals.push({
        id: "ports",
        severity: unusualPorts.length >= 2 ? "medium" : "low",
        title: "Non-standard exposed ports",
        detail: `Passive enrichment saw open port(s) ${unusualPorts.join(", ")}, which may expand the service attack surface.`,
      });
    }

    return {
      signals: dedupeById(signals),
      flags: {
        brandImpersonation: Boolean(brand),
        financialTerms: financialTermsHit,
        insecureHttp: parsedUrl?.protocol === "http:",
        downloadLure: downloadTermsHit,
        unusualPorts: unusualPorts.length > 0,
      },
      parsedUrl,
      hostname,
    };
  }

  function buildFacts(parsedUrl, hostname, data, vt) {
    const route = parsedUrl ? `${parsedUrl.pathname || "/"}${parsedUrl.search || ""}` : "-";
    const hostType = hostname ? (isIpHostname(hostname) ? "IP address" : "Domain") : "Unknown";

    return [
      {
        label: "Risk band",
        value: `${scoreBand(data.riskScore)} (${data.riskScore}%)`,
      },
      {
        label: "Protocol",
        value: parsedUrl?.protocol ? parsedUrl.protocol.replace(":", "").toUpperCase() : "Unknown",
      },
      {
        label: "Host type",
        value: hostType,
      },
      {
        label: "Route",
        value: route || "/",
      },
      {
        label: "Engines",
        value: vt.detection_ratio || `${vt.total_engines || 0} checked`,
      },
      {
        label: "Ports",
        value: summarizePorts(data.openPorts),
      },
    ];
  }

  function analyzeScan(scan) {
    const url = scan?.original_input || scan?.currentUrl || scan?.scan_target || scan?.url || "";
    const verdict = normalizeVerdict(scan?.verdict);
    const riskScore = Number(scan?.risk_score ?? scan?.riskScore ?? 0);
    const canonicalDomain = scan?.canonical_domain || scan?.canonicalDomain || "";
    const virusTotal = scan?.virus_total || scan?.virusTotal || {};
    const openPorts = normalizePorts(scan?.open_ports || scan?.openPorts || []);
    const portsLastUpdated = scan?.ports_last_updated || scan?.portsLastUpdated || "";
    const detectionRatio = virusTotal.detection_ratio || `${virusTotal.malicious_count || 0}/${virusTotal.total_engines || 0}`;
    const engineCoverage = Number(virusTotal.total_engines || 0);

    const signalResult = buildSignals({
      url,
      canonicalDomain,
      verdict,
      riskScore,
      virusTotal,
      openPorts,
    });

    const confidence = buildConfidenceLabel(verdict, riskScore, virusTotal, signalResult.signals);
    const facts = buildFacts(
      signalResult.parsedUrl,
      signalResult.hostname,
      { riskScore, openPorts, portsLastUpdated },
      virusTotal,
    );

    return {
      verdict,
      riskScore,
      url,
      canonicalDomain: canonicalDomain || signalResult.hostname || "",
      engineCoverage,
      detectionRatio,
      openPorts,
      portsLastUpdated,
      signals: signalResult.signals.length
        ? signalResult.signals
        : [
            {
              id: "clean",
              severity: "low",
              title: "No elevated URL-pattern indicators",
              detail: "The quick scan did not surface any strong phishing, typo, or transport anomalies from the current URL shape.",
            },
          ],
      actions: buildActions(verdict, signalResult.flags),
      facts,
      confidence,
      headline: buildHeadline(verdict, riskScore),
      summary: buildSummary(verdict, riskScore, signalResult.signals, virusTotal),
      portsSummary: summarizePorts(openPorts),
    };
  }

  window.SecureLensIntel = {
    analyzeScan,
  };
})();
