document.addEventListener("DOMContentLoaded", () => {
  const canvas = document.getElementById("verdictChart");
  const rowsBody = document.getElementById("dashboardRows");

  if (canvas) {
    initVerdictChart(
      parseInt(canvas.dataset.safe || "0", 10),
      parseInt(canvas.dataset.suspicious || "0", 10),
      parseInt(canvas.dataset.malicious || "0", 10),
    );
  }

  const refreshRows = async () => {
    if (!rowsBody) return;
    try {
      const response = await fetch("/partials/dashboard_rows", {
        headers: { "X-Requested-With": "fetch" },
      });
      if (!response.ok) return;
      rowsBody.innerHTML = await response.text();
    } catch (error) {
      console.error("Failed to refresh dashboard rows:", error);
    }
  };

  if (rowsBody) {
    window.setInterval(refreshRows, 5000);
  }
});

async function deleteScan(scanId) {
  if (
    !confirm(
      "Are you sure you want to delete this report? This action cannot be undone.",
    )
  ) {
    return;
  }

  try {
    const response = await fetch(`/api/scan/${scanId}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
    });

    if (response.ok) {
      showToast("Report deleted successfully", "success");
      window.setTimeout(() => window.location.reload(), 700);
      return;
    }

    const data = await response.json();
    showToast(data.detail || "Failed to delete report", "error");
  } catch (error) {
    console.error("Error deleting scan:", error);
    showToast("An error occurred while deleting the report", "error");
  }
}

window.deleteScan = deleteScan;
