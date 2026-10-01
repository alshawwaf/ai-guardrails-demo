// ============================================
// Dashboard Page Module
// Feed items come from stored logs (attacker-controllable): rendered with
// textContent / DOM only; badge colours come from the fixed palette.
// ============================================

import { apiFetch, createDetectorBadge, getAttackColor, getDetectorLabel } from "../shared/utils.js";

/**
 * Initialize dashboard page
 */
export function initDashboard() {
  const refreshBtn = document.getElementById("refresh-btn");
  const timelineRange = document.getElementById("timeline-range");
  let timelineChartInstance = null;

  if (refreshBtn) refreshBtn.addEventListener("click", () => loadAnalytics());
  if (timelineRange) timelineRange.addEventListener("change", () => loadAnalytics());

  // PDF Export
  const exportPdfBtn = document.getElementById("export-pdf");
  if (exportPdfBtn) {
    exportPdfBtn.addEventListener("click", () => {
      window.print();
    });
  }

  // Set print date
  const dashboardWrapper = document.querySelector('.dashboard-wrapper');
  if (dashboardWrapper) {
      dashboardWrapper.setAttribute('data-print-date', new Date().toLocaleString());
  }

  // Initial load
  loadAnalytics();
  // Auto-refresh every 30s
  setInterval(() => loadAnalytics(), 30000);

  async function loadAnalytics() {
    try {
      const range = timelineRange ? timelineRange.value : "24h";
      // apiFetch sends the browser to /login when the session has ended (401).
      const response = await apiFetch(`/api/analytics?range=${encodeURIComponent(range)}`);
      const data = await response.json();
      if (!response.ok || !data || typeof data !== "object") {
        // Keep what is on screen; never render an error body as statistics.
        throw new Error((data && data.error) || `Analytics request failed (HTTP ${response.status})`);
      }

      // Update stats and feed first (critical info)
      try {
        updateStats(data);
      } catch (e) {
        console.error("Error updating stats:", e);
      }

      try {
        updateFeed(data.recent_logs);
      } catch (e) {
        console.error("Error updating feed:", e);
      }

      // Update charts last (might fail if Chart.js not loaded)
      try {
        if (typeof Chart !== "undefined") {
          updateCharts(data);
        } else {
          console.warn("Chart.js not loaded, skipping charts.");
        }
      } catch (e) {
        console.error("Error updating charts:", e);
      }
    } catch (error) {
      console.error("Failed to load analytics:", error);
    }
  }

  function updateStats(data) {
    const num = (v) => (Number.isFinite(Number(v)) ? String(v) : "–");
    const totalScansEl = document.getElementById("total-scans");
    if (totalScansEl) totalScansEl.textContent = num(data.total_scans);

    const threatsBlockedEl = document.getElementById("threats-blocked");
    if (threatsBlockedEl) threatsBlockedEl.textContent = num(data.threats_blocked);

    const successRate = document.getElementById("success-rate");
    if (successRate) {
      successRate.textContent = Number.isFinite(Number(data.success_rate)) ? `${data.success_rate}%` : "–";
    }
  }

  function updateCharts(data) {
    // Threat Distribution Chart
    const ctxThreat = document.getElementById("threatChart");
    if (ctxThreat) {
      const ctx = ctxThreat.getContext("2d");
      const threatLabels = Object.keys(data.threat_distribution || {});
      const threatValues = Object.values(data.threat_distribution || {});

      // Generate colors based on attack type
      const threatColors = threatLabels.map((label) => getAttackColor(label));
      // Chart.js draws on canvas (no HTML); show friendly detector labels.
      const threatDisplayLabels = threatLabels.map((label) => getDetectorLabel(label));

      if (window.threatChartInstance) window.threatChartInstance.destroy();

      window.threatChartInstance = new Chart(ctx, {
        type: "bar",
        data: {
          labels: threatLabels.length > 0 ? threatDisplayLabels : ["No Data"],
          datasets: [
            {
              label: "Threats",
              data: threatValues.length > 0 ? threatValues : [0],
              backgroundColor:
                threatValues.length > 0
                  ? threatColors
                  : ["rgba(100, 116, 139, 0.3)"],
              borderWidth: 1,
              borderColor: "rgba(255, 255, 255, 0.1)",
              borderRadius: 4,
              barPercentage: 0.6,
            },
          ],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "rgba(13, 17, 23, 0.9)",
              titleColor: "#fff",
              bodyColor: "#cbd5e1",
              borderColor: "rgba(255,255,255,0.1)",
              borderWidth: 1,
              padding: 10,
              displayColors: true,
              callbacks: {
                label: function (context) {
                  return ` ${context.parsed.x} detected`;
                },
              },
            },
          },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: "rgba(255, 255, 255, 0.05)" },
              ticks: { color: "#94a3b8", precision: 0 },
            },
            y: {
              grid: { display: false },
              ticks: { color: "#cbd5e1", font: { weight: 500 } },
            },
          },
          onClick: (event, elements) => {
            if (elements.length > 0) {
              const index = elements[0].index;
              const label = threatLabels[index];
              window.location.href = `/logs?filter=${encodeURIComponent(
                label
              )}`;
            }
          },
        },
      });
    }

    // Timeline Chart
    const ctxTimeline = document.getElementById("timelineChart");
    if (ctxTimeline) {
      const ctx = ctxTimeline.getContext("2d");
      const timeline = data.timeline || {};
      const timelineLabels = Object.keys(timeline).sort();
      const timelineValues = timelineLabels.map((k) => timeline[k]);

      if (timelineChartInstance) timelineChartInstance.destroy();

      timelineChartInstance = new Chart(ctx, {
        type: "bar",
        data: {
          labels: timelineLabels,
          datasets: [
            {
              label: "Scans",
              data: timelineValues,
              backgroundColor: "rgba(59, 130, 246, 0.5)",
              borderColor: "#3b82f6",
              borderWidth: 1,
              borderRadius: 4,
              barPercentage: 0.6,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              mode: "index",
              intersect: false,
              backgroundColor: "rgba(13, 17, 23, 0.9)",
              titleColor: "#fff",
              bodyColor: "#cbd5e1",
              borderColor: "rgba(255,255,255,0.1)",
              borderWidth: 1,
              padding: 10,
              displayColors: false,
            },
          },
          scales: {
            y: {
              beginAtZero: true,
              grid: { color: "rgba(255, 255, 255, 0.05)" },
              ticks: { color: "#94a3b8" },
            },
            x: {
              grid: { display: false },
              ticks: { color: "#94a3b8", maxTicksLimit: 8 },
            },
          },
          interaction: {
            mode: "nearest",
            axis: "x",
            intersect: false,
          },
        },
      });
    }
  }

  function updateFeed(logs) {
    const feedList = document.getElementById("feed-list");
    if (!feedList) return;
    feedList.replaceChildren();

    if (!Array.isArray(logs) || logs.length === 0) {
      const empty = document.createElement("p");
      empty.style.color = "var(--text-secondary)";
      empty.style.padding = "2rem";
      empty.style.textAlign = "center";
      empty.textContent = "No recent activity";
      feedList.appendChild(empty);
      return;
    }

    const div = (cls, text) => {
      const d = document.createElement("div");
      if (cls) d.className = cls;
      if (text !== undefined) d.textContent = text;
      return d;
    };
    const span = (cls, text) => {
      const sp = document.createElement("span");
      if (cls) sp.className = cls;
      sp.textContent = text;
      return sp;
    };

    logs.forEach((log) => {
      const item = div("feed-item");

      // Make clickable
      item.style.cursor = "pointer";
      item.addEventListener("click", () => {
        window.location.href = "/logs";
      });

      // A failed scan (fail-closed: the prompt never reached the model) is an
      // error, never "Safe" (same rule as the Logs page).
      const isError = !!(log.error || log.result?.guardrails_error);
      const isFlagged = !isError && (log.result?.flagged || false);
      const statusClass = isFlagged || isError ? "status-danger" : "status-safe";
      const statusIcon = isFlagged || isError ? "⚠️" : "✅";

      const prompt = log.prompt == null ? "" : String(log.prompt);
      const promptPreview =
        prompt.length > 80
          ? prompt.substring(0, 80) + "..."
          : prompt;

      const content = div("feed-content");
      content.appendChild(div("feed-prompt", promptPreview));

      // Attack vector badges
      if (Array.isArray(log.attack_vectors) && log.attack_vectors.length > 0) {
        const vectors = div("feed-vectors");
        log.attack_vectors.forEach((v, i) => {
          if (i > 0) vectors.appendChild(document.createTextNode(" "));
          vectors.appendChild(createDetectorBadge(v, "vector-badge"));
        });
        content.appendChild(vectors);
      }

      const meta = div("feed-meta");
      meta.appendChild(span("", log.timestamp == null ? "" : String(log.timestamp)));
      meta.appendChild(isError
        ? span("feed-badge", "Scan failed")
        : isFlagged
          ? span("feed-badge", "Threat Detected")
          : span("feed-badge-safe", "Safe"));
      content.appendChild(meta);

      item.append(div(`feed-icon ${statusClass}`, statusIcon), content);
      feedList.appendChild(item);
    });
  }
}
