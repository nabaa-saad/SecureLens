function createToastContainer() {
  const container = document.createElement("div");
  container.id = "toast-container";
  document.body.appendChild(container);
  return container;
}

function showToast(message, type = "info", duration = 5000) {
  const container =
    document.getElementById("toast-container") || createToastContainer();

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;

  const icons = {
    success: "ph-fill ph-check-circle",
    error: "ph-fill ph-x-circle",
    info: "ph-fill ph-info",
    warning: "ph-fill ph-warning",
  };

  toast.innerHTML = `
    <i class="${icons[type] || icons.info} text-2xl"></i>
    <span class="flex-1 font-medium">${message}</span>
    <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white transition-colors">
      <i class="ph ph-x text-xl"></i>
    </button>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("removing");
    setTimeout(() => toast.remove(), 500);
  }, duration);
}

function createToastContainer() {
  const container = document.createElement("div");
  container.id = "toast-container";
  document.body.appendChild(container);
  return container;
}

window.showToast = showToast;
async function pasteUrl() {
  try {
    const text = await navigator.clipboard.readText();
    const input = document.getElementById("urlInput");
    if (input) {
      input.value = text;
      input.dispatchEvent(new Event("input"));
      input.focus();
      showToast("URL pasted from clipboard", "success", 2000);
    }
  } catch (err) {
    showToast("Failed to paste from clipboard", "error", 3000);
  }
}

window.pasteUrl = pasteUrl;
function showLoader() {
  const overlay = document.getElementById("loadingOverlay");
  if (overlay) {
    overlay.classList.add("active");
    overlay.style.opacity = "0";
    overlay.style.visibility = "visible";

    // Hide the top accent bar during loading
    const accentBar = document.getElementById("topAccentBar");
    if (accentBar) {
      accentBar.style.display = "none";
    }

    setTimeout(() => {
      overlay.style.opacity = "1";
    }, 10);
  }
}

function hideLoader() {
  const overlay = document.getElementById("loadingOverlay");
  if (overlay) {
    overlay.style.opacity = "0";
    setTimeout(() => {
      overlay.style.visibility = "hidden";
      overlay.classList.remove("active");

      // Restore the top accent bar
      const accentBar = document.getElementById("topAccentBar");
      if (accentBar) {
        accentBar.style.display = "";
      }
    }, 300);
  }
}

window.showLoader = showLoader;
window.hideLoader = hideLoader;
function initVerdictChart(safe, suspicious, malicious) {
  const canvas = document.getElementById("verdictChart");
  if (!canvas || typeof Chart === "undefined") return;

  const isDark = document.documentElement.classList.contains("dark");
  const textColor = isDark ? "#e2e8f0" : "#1e293b";

  new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: ["Safe", "Suspicious", "Malicious"],
      datasets: [
        {
          data: [safe, suspicious, malicious],
          backgroundColor: [
            "rgba(16, 185, 129, 0.8)",
            "rgba(245, 158, 11, 0.8)",
            "rgba(239, 68, 68, 0.8)",
          ],
          borderColor: ["#10b981", "#f59e0b", "#ef4444"],
          borderWidth: 2,
          hoverOffset: 12,
          hoverBorderWidth: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "70%",
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            usePointStyle: true,
            padding: 20,
            color: textColor,
            font: {
              family: "'Inter', sans-serif",
              size: 13,
              weight: "600",
            },
          },
        },
        tooltip: {
          backgroundColor: isDark
            ? "rgba(30, 41, 59, 0.95)"
            : "rgba(255, 255, 255, 0.95)",
          titleColor: textColor,
          bodyColor: textColor,
          borderColor: isDark ? "#475569" : "#e2e8f0",
          borderWidth: 1,
          padding: 16,
          cornerRadius: 12,
          displayColors: true,
          callbacks: {
            label: function (context) {
              const label = context.label || "";
              const value = context.parsed || 0;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = ((value / total) * 100).toFixed(1);
              return `${label}: ${value} (${percentage}%)`;
            },
          },
        },
      },
      animation: {
        animateRotate: true,
        animateScale: true,
        duration: 1200,
        easing: "easeInOutQuart",
      },
    },
  });
}

window.initVerdictChart = initVerdictChart;
function copyToClipboard(text, successMessage = "Copied to clipboard!") {
  navigator.clipboard
    .writeText(text)
    .then(() => showToast(successMessage, "success", 2000))
    .catch(() => showToast("Failed to copy", "error", 2000));
}

window.copyToClipboard = copyToClipboard;
function animateCounter(element, target, duration = 1500) {
  const start = 0;
  const increment = target / (duration / 16);
  let current = start;

  const timer = setInterval(() => {
    current += increment;
    if (current >= target) {
      current = target;
      clearInterval(timer);
    }
    element.textContent = Math.floor(current);
  }, 16);
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-counter]").forEach((el) => {
    const target = parseInt(el.dataset.counter, 10);
    if (!isNaN(target)) {
      setTimeout(() => animateCounter(el, target), 500);
    }
  });
});
