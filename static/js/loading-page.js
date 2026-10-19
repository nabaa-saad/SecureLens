document.addEventListener("DOMContentLoaded", () => {
  const dataNode = document.getElementById("loading-page-data");
  if (!dataNode) return;

  const data = JSON.parse(dataNode.textContent || "{}");
  const scanId = data.scanId;
  const statusText = document.getElementById("statusText");
  const loaderIcon = document.getElementById("loaderIcon");
  const progressBar = document.getElementById("progressBar");
  const progressOrb = document.getElementById("progressOrb");
  const progressPulse = document.getElementById("progressPulse");
  const progressPercent = document.getElementById("progressPercent");
  const progressPercentLabel = document.getElementById("progressPercentLabel");
  const phaseLabel = document.getElementById("phaseLabel");
  const elapsedTime = document.getElementById("elapsedTime");
  const feed = document.getElementById("activityFeed");
  const constellationNodes = Array.from(
    document.querySelectorAll("#progressConstellation .constellation-node"),
  );
  const activityMessages = new Set([
    "Preparing the staged analysis pipeline...",
  ]);

  const updateStepState = (activeStep, completedStep = 0) => {
    for (let i = 1; i <= 4; i += 1) {
      const step = document.getElementById(`step${i}`);
      let state = "idle";
      if (i <= completedStep) {
        state = "completed";
      } else if (i === activeStep) {
        state = "active";
      }
      if (step) step.dataset.state = state;
    }
  };

  const updateConstellation = (percent) => {
    const activeNodes = Math.max(
      1,
      Math.min(
        constellationNodes.length,
        Math.ceil((percent / 100) * constellationNodes.length),
      ),
    );
    constellationNodes.forEach((node, index) => {
      node.classList.remove("is-active", "is-complete");
      if (index < activeNodes - 1) {
        node.classList.add("is-complete");
      } else if (index === activeNodes - 1) {
        node.classList.add("is-active");
      }
    });
  };

  const updateOrbVisual = (percent, step) => {
    const normalized = Math.max(0.03, percent / 100);
    progressOrb?.style.setProperty("--orb-progress", normalized.toFixed(2));
    if (progressPulse) {
      progressPulse.style.opacity = String(0.35 + normalized * 0.5);
    }
    if (progressPercent) progressPercent.textContent = `${percent}%`;
    if (progressPercentLabel) progressPercentLabel.textContent = `${percent}%`;

    const stepPalettes = {
      1: ["#38bdf8", "#22d3ee"],
      2: ["#34d399", "#38bdf8"],
      3: ["#a855f7", "#38bdf8"],
      4: ["#22c55e", "#10b981"],
    };
    const colors = stepPalettes[step] || stepPalettes[1];
    if (progressBar) {
      progressBar.style.background = `linear-gradient(90deg, ${colors[0]}, ${colors[1]}, #38bdf8)`;
    }
  };

  const labelForStep = (step) => {
    if (step === 1) return "Collecting Foundation Signals";
    if (step === 2) return "Running Security Scanners";
    if (step === 3) return "Correlating Findings";
    if (step === 4) return "Finalizing Report";
    return "Preparing Scan Queue";
  };

  const appendActivity = (message, tone = "text-slate-400") => {
    if (!message || activityMessages.has(message) || !feed) return;
    activityMessages.add(message);
    const line = document.createElement("div");
    line.className = `activity-line ${tone}`;
    line.innerHTML = `<i class="ph ph-caret-right"></i><span>${message}</span>`;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
  };

  const applyLiveProgress = (response) => {
    const step = Number(response.progress_step || 1);
    const percent = Math.max(
      3,
      Math.min(100, Number(response.progress_percent || 3)),
    );
    const message =
      response.progress_message ||
      "Preparing the staged analysis pipeline...";

    if (statusText) statusText.textContent = message;
    if (phaseLabel) phaseLabel.textContent = labelForStep(step);
    if (progressBar) progressBar.style.width = `${percent}%`;
    updateStepState(step, Math.max(0, step - 1));
    updateOrbVisual(percent, step);
    updateConstellation(percent);
    appendActivity(message);
  };

  let elapsedSeconds = 0;
  const elapsedInterval = window.setInterval(() => {
    elapsedSeconds += 1;
    if (elapsedTime) elapsedTime.textContent = `${elapsedSeconds}s`;
  }, 1000);

  let pollHandle = null;
  const stopPolling = () => {
    if (pollHandle) {
      window.clearInterval(pollHandle);
      pollHandle = null;
    }
    window.clearInterval(elapsedInterval);
  };

  const applyTerminalState = (response) => {
    if (response.status === "COMPLETED") {
      if (statusText) statusText.textContent = "Analysis complete! Redirecting...";
      if (loaderIcon) {
        loaderIcon.className =
          "ph-fill ph-check-circle text-emerald-400 text-4xl";
      }
      if (phaseLabel) phaseLabel.textContent = "Finalizing Report";
      if (progressBar) progressBar.style.width = "100%";
      updateStepState(4, 4);
      updateOrbVisual(100, 4);
      updateConstellation(100);
      appendActivity("Scan completed successfully!", "text-emerald-400 font-bold");
      window.setTimeout(() => {
        window.location.href = response.redirect;
      }, 500);
      return;
    }

    if (response.status === "FAILED") {
      if (statusText) {
        statusText.textContent =
          response.progress_message || "Scan failed. Please try again.";
      }
      if (loaderIcon) {
        loaderIcon.className = "ph-fill ph-x-circle text-red-400 text-4xl";
      }
      if (progressBar) progressBar.style.width = "100%";
      const failedStep = Number(response.progress_step || 4);
      if (phaseLabel) phaseLabel.textContent = "Scan Interrupted";
      updateStepState(failedStep, Math.max(0, failedStep - 1));
      updateOrbVisual(100, failedStep);
      updateConstellation(100);
      appendActivity(
        response.progress_message || "Scan failed.",
        "text-red-400 font-bold",
      );
      return;
    }

    if (statusText) {
      statusText.textContent =
        "This scan is no longer available or this browser no longer has access to it.";
    }
    if (loaderIcon) {
      loaderIcon.className =
        "ph-fill ph-warning-circle text-amber-400 text-4xl";
    }
    if (phaseLabel) phaseLabel.textContent = "Scan Not Available";
  };

  const pollStatus = async () => {
    try {
      const response = await fetch(`/status/${scanId}`, {
        headers: { "X-Requested-With": "fetch" },
      });
      if (!response.ok) return;
      const payload = await response.json();
      if (payload.status === "PENDING") {
        applyLiveProgress(payload);
        return;
      }
      stopPolling();
      applyTerminalState(payload);
    } catch (error) {
      console.error("Error polling scan status:", error);
    }
  };

  updateStepState(1, 0);
  updateOrbVisual(3, 1);
  updateConstellation(3);
  pollHandle = window.setInterval(pollStatus, 2000);
  pollStatus();

  window.cancelScan = async function cancelScan() {
    if (!confirm("Are you sure you want to cancel this scan?")) {
      return;
    }

    const cancelBtn = document.getElementById("cancelBtn");
    if (cancelBtn) {
      cancelBtn.disabled = true;
      cancelBtn.innerHTML =
        '<i class="ph ph-spinner text-xl animate-spin"></i><span>Cancelling...</span>';
    }

    try {
      const response = await fetch(`/api/scan/${scanId}/cancel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      if (response.ok) {
        stopPolling();
        window.location.href = "/";
        return;
      }

      const data = await response.json();
      alert(data.detail || "Failed to cancel scan");
    } catch (error) {
      console.error("Error cancelling scan:", error);
      alert("Failed to cancel scan. Please try again.");
    }

    if (cancelBtn) {
      cancelBtn.disabled = false;
      cancelBtn.innerHTML =
        '<i class="ph ph-x-circle text-xl group-hover:animate-pulse"></i><span>Cancel Scan</span>';
    }
  };
});
