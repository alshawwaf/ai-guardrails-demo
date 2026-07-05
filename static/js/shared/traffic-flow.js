// ============================================
// Traffic Flow Visualization Module
// ============================================

import { getAttackColor } from "./utils.js";
import { renderScanPipeline, renderScanningPipeline } from "./pipeline.js";

/**
 * Open the result modal in a "scanning…" progress state while /api/analyze
 * runs. displayResults() replaces this content when the response arrives.
 */
export function showScanning({ useInbound, useOutbound, provider, model }) {
  const modal = document.getElementById("result-modal");
  if (!modal) return;
  const modalHeader = modal.querySelector(".modal-header");
  const flagsContainer = document.getElementById("flags-container");
  const statsContainer = document.getElementById("result-stats");
  if (flagsContainer) flagsContainer.innerHTML = "";
  if (statsContainer) statsContainer.innerHTML = "";
  modalHeader.className = "modal-header compact-header neutral";
  modalHeader.innerHTML =
    '<div class="compact-header-left">' +
    '<span class="compact-status-badge" style="--status-color: #7c3aed">' +
    '<span class="status-icon">⏳</span><span class="status-text">Scanning…</span></span></div>' +
    '<button class="close-modal-btn" id="close-result-modal">&times;</button>';
  const card = document.createElement("div");
  card.className = "modal-card compact-flow-card";
  card.appendChild(renderScanningPipeline({ useInbound, useOutbound, provider, model }));
  flagsContainer.appendChild(card);
  const closeBtn = document.getElementById("close-result-modal");
  if (closeBtn) closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
  modal.classList.remove("hidden");
}

/**
 * Display analysis results in modal
 * @param {Object} data - Analysis result data
 */
export function displayResults(data) {
  const modal = document.getElementById("result-modal");
  const modalHeader = modal.querySelector(".modal-header");
  const flagsContainer = document.getElementById("flags-container");
  const statsContainer = document.getElementById("result-stats");

  // Reset content
  flagsContainer.innerHTML = "";
  if (statsContainer) statsContainer.innerHTML = "";

  if (data.isComparison) {
    // --- Comparison View Logic ---
    modalHeader.className = `modal-header compact-header neutral`;
    modalHeader.innerHTML = `
      <div class="compact-header-left">
        <span class="compact-status-badge" style="--status-color: var(--primary-color)">
          <span class="status-icon">📊</span>
          <span class="status-text">Market Comparison</span>
        </span>
        <span class="compact-model-badge">AI Guardrails vs Competitors</span>
      </div>
      <button class="close-modal-btn" id="close-result-modal">&times;</button>
    `;

    const comparisonContainer = document.createElement("div");
    comparisonContainer.className = "comparison-view";

    // Chart Section
    const chartCard = document.createElement("div");
    chartCard.className = "modal-card comparison-chart-card";
    chartCard.innerHTML = `<canvas id="comparison-chart" height="150"></canvas>`;
    comparisonContainer.appendChild(chartCard);

    // Vendor Details Section
    const vendorGrid = document.createElement("div");
    vendorGrid.className = "vendor-comparison-grid";

    data.results.forEach(res => {
      const vendorCard = document.createElement("div");
      const isError = !!res.error;
      const vendorClass = isError ? 'error' : (res.flagged ? 'flagged' : 'safe');
      vendorCard.className = `vendor-card ${vendorClass}`;

      const statusColor = isError ? "#f97316" : (res.flagged ? "#ef4444" : "#22c55e");
      const statusIcon = isError ? "⚠️" : (res.flagged ? "⛔" : "✓");

      vendorCard.innerHTML = `
        <div class="vendor-info">
          <div class="vendor-header">
            <span class="vendor-name">${res.vendor}</span>
            <span class="vendor-status" style="color: ${statusColor}">${statusIcon}</span>
          </div>
          <div class="vendor-score-bar">
            <div class="score-fill" style="width: ${res.score}%; background: ${statusColor}"></div>
          </div>
          <div class="vendor-score-text">${isError ? 'Service Error' : `${res.score}% Threat Confidence`}</div>
          <div class="vendor-details">
            ${res.details && res.details.length > 0
          ? res.details.map(d => `<span class="detail-pill">${d}</span>`).join('')
          : '<span class="detail-pill">No threats detected</span>'}
          </div>
        </div>
      `;
      vendorGrid.appendChild(vendorCard);
    });

    comparisonContainer.appendChild(vendorGrid);
    flagsContainer.appendChild(comparisonContainer);

    // Initialize Chart (wait for DOM)
    setTimeout(() => {
      const chartCanvas = document.getElementById('comparison-chart');
      if (!chartCanvas) return;

      const ctx = chartCanvas.getContext('2d');
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: data.results.map(r => r.vendor),
          datasets: [{
            label: 'Threat Confidence Score',
            data: data.results.map(r => r.score || 0),
            backgroundColor: data.results.map(r => r.flagged ? 'rgba(239, 68, 68, 0.7)' : 'rgba(34, 197, 94, 0.7)'),
            borderColor: data.results.map(r => r.flagged ? '#ef4444' : '#22c55e'),
            borderWidth: 2,
            borderRadius: 6,
            borderSkipped: false,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: {
            duration: 1500,
            easing: 'easeOutQuart'
          },
          scales: {
            y: {
              beginAtZero: true,
              max: 100,
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: {
                color: 'rgba(255, 255, 255, 0.5)',
                callback: function (value) { return value + '%'; }
              }
            },
            x: {
              grid: { display: false },
              ticks: { color: 'rgba(255, 255, 255, 0.8)' }
            }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: 'rgba(15, 23, 42, 0.9)',
              titleColor: '#fff',
              bodyColor: '#cbd5e1',
              padding: 12,
              cornerRadius: 8,
              displayColors: false
            }
          }
        }
      });
    }, 50);

  } else {
    // --- Standard View Logic (Existing) ---
    const guardrailsResult = data.guardrails_result;
    const guardrailsOutboundResult = data.guardrails_outbound_result;
    const isFlagged = data.flagged;
    const isOutboundFlagged =
      guardrailsOutboundResult && guardrailsOutboundResult.flagged;

    let headerClass, statusIcon, statusText, statusColor;

    if (!guardrailsResult) {
      headerClass = "neutral";
      statusIcon = "○";
      statusText = "Not Scanned";
      statusColor = "var(--text-secondary)";
    } else if (isFlagged) {
      headerClass = "danger";
      statusIcon = "⛔";
      statusText = "Threat Blocked";
      statusColor = "#ef4444";
    } else if (isOutboundFlagged) {
      headerClass = "warning";
      statusIcon = "⚠️";
      statusText = "Outbound Threat";
      statusColor = "#f97316";
    } else {
      headerClass = "success";
      statusIcon = "✓";
      statusText = "Safe";
      statusColor = "#22c55e";
    }

    let providerLabel = "OpenAI";
    if (data.model_provider === "azure") providerLabel = "Azure";
    else if (data.model_provider === "gemini") providerLabel = "Gemini";
    else if (data.model_provider === "anthropic") providerLabel = "Claude";
    else if (data.model_provider === "ollama") providerLabel = "Ollama";

    const modelDisplay = data.model_name ? `${providerLabel} · ${data.model_name}` : providerLabel;

    modalHeader.className = `modal-header compact-header ${headerClass}`;
    modalHeader.innerHTML = `
      <div class="compact-header-left">
        <span class="compact-status-badge" style="--status-color: ${statusColor}">
          <span class="status-icon">${statusIcon}</span>
          <span class="status-text">${statusText}</span>
        </span>
        <span class="compact-model-badge">${modelDisplay}</span>
      </div>
      <button class="close-modal-btn" id="close-result-modal">&times;</button>
    `;

    const flowCard = document.createElement("div");
    flowCard.className = "modal-card compact-flow-card";

    const useGuardrails = document.getElementById("guardrails-scan-checkbox").checked;
    const useGuardrailsOutbound = document.getElementById(
      "guardrails-outbound-checkbox"
    ).checked;

    const flowDiagram = renderTrafficFlow(data, useGuardrails, useGuardrailsOutbound);
    flowDiagram.classList.add("modal-pipeline");
    flowCard.appendChild(flowDiagram);
    flagsContainer.appendChild(flowCard);

    const inboundVectors =
      guardrailsResult && guardrailsResult.attack_vectors
        ? guardrailsResult.attack_vectors
        : [];
    const outboundVectors = [];

    if (guardrailsOutboundResult && guardrailsOutboundResult.breakdown) {
      guardrailsOutboundResult.breakdown.forEach((r) => {
        if (r.detected && r.detector_type) {
          const vectorName = r.detector_type.split("/").pop();
          if (!outboundVectors.includes(vectorName)) {
            outboundVectors.push(vectorName);
          }
        }
      });
    }

    if (inboundVectors.length > 0 || outboundVectors.length > 0) {
      const threatSection = document.createElement("div");
      threatSection.className = "compact-threat-section";

      const threatLabel = document.createElement("span");
      threatLabel.className = "threat-section-label";
      threatLabel.textContent = "Detected:";
      threatSection.appendChild(threatLabel);

      const pillContainer = document.createElement("div");
      pillContainer.className = "threat-pills";

      [...inboundVectors, ...outboundVectors].forEach((vector) => {
        const pill = document.createElement("span");
        pill.className = "threat-pill";
        const color = getAttackColor(vector);
        pill.style.setProperty("--pill-color", color);
        pill.textContent = vector.replace(/_/g, " ");
        pillContainer.appendChild(pill);
      });

      threatSection.appendChild(pillContainer);
      flagsContainer.appendChild(threatSection);
    }

    const detailsPane = document.createElement("div");
    detailsPane.id = "flow-details-pane";
    detailsPane.className = "hidden";
    flagsContainer.appendChild(detailsPane);

    if (data.openai_response) {
      const responseSection = document.createElement("div");
      responseSection.className = "compact-response-section";

      const responseHeader = document.createElement("div");
      responseHeader.className = "response-header";
      responseHeader.innerHTML = `<span class="response-label">${providerLabel} Response</span>`;
      responseSection.appendChild(responseHeader);

      const responseBox = document.createElement("div");
      responseBox.className = "compact-response-box";
      responseBox.textContent = data.openai_response;
      responseSection.appendChild(responseBox);

      flagsContainer.appendChild(responseSection);
    }
  }

  // Re-attach close handler
  const closeBtn = document.getElementById("close-result-modal");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      modal.classList.add("hidden");
    });
  }

  modal.classList.remove("hidden");
}

/**
 * Create attack card element
 * @param {string} vector - Attack vector name
 * @returns {HTMLElement} Card element
 */
function createAttackCard(vector) {
  const card = document.createElement("div");
  card.className = "attack-type-card";
  card.style.display = "flex";
  card.style.flexDirection = "row";
  card.style.alignItems = "center";

  const color = getAttackColor(vector);

  card.style.setProperty("--attack-color", color);
  card.style.background = `${color}15`;
  card.style.borderColor = `${color}40`;
  card.style.borderLeft = `3px solid ${color}`;

  card.innerHTML = `
        <span class="attack-name" style="margin-left: 0;">${vector.replace(
    /_/g,
    " "
  )}</span>
    `;
  return card;
}

/**
 * Render traffic flow diagram
 * @param {Object} data - Analysis result data
 * @param {boolean} useGuardrails - Whether inbound scan is enabled
 * @param {boolean} useGuardrailsOutbound - Whether outbound scan is enabled
 * @returns {HTMLElement} Traffic flow container
 */
function renderTrafficFlow(data, useGuardrails, useGuardrailsOutbound) {
  // Modernized: delegates to the shared pipeline renderer (components/
  // pipeline.css). Node clicks still open the JSON detail pane below.
  return renderScanPipeline(data, useGuardrails, useGuardrailsOutbound, (id) =>
    showStepDetails(id, data)
  );
}

/**
 * Show details pane for a traffic flow step
 * @param {string} stepId - Step identifier
 * @param {Object} data - Analysis result data
 */
function showStepDetails(stepId, data) {
  const pane = document.getElementById("flow-details-pane");
  if (!pane) return;

  let title = "";
  let content = "";

  switch (stepId) {
    case "user":
      title = "User Input";
      content = data.prompt || "No prompt data available.";
      break;
    case "inbound":
      title = "Demo Inbound Scan";
      content = data.guardrails_result
        ? JSON.stringify(data.guardrails_result, null, 2)
        : "No scan performed.";
      break;
    case "llm":
      if (data.model_provider === "azure") {
        title = "Azure OpenAI Response";
      } else if (data.model_provider === "gemini") {
        title = "Google Gemini Response";
      } else if (data.model_provider === "ollama") {
        title = "Ollama Response";
      } else {
        title = "OpenAI Response";
      }
      content = data.openai_response || "No response generated.";
      break;
    case "outbound":
      title = "Demo Outbound Scan";
      content = data.guardrails_outbound_result
        ? JSON.stringify(data.guardrails_outbound_result, null, 2)
        : "No scan performed.";
      break;
    case "user-response":
      title = "Response Delivered to User";
      content =
        data.openai_response ||
        "No response was delivered (blocked or not generated).";
      break;
  }

  pane.innerHTML = `
        <div class="flow-details-header">
            <div class="flow-details-title">${title}</div>
            <div style="display: flex; gap: 0.5rem; align-items: center;">
                <button class="copy-btn" onclick="navigator.clipboard.writeText(this.parentElement.parentElement.nextElementSibling.textContent).then(() => { this.textContent = 'Copied!'; setTimeout(() => this.textContent = 'Copy', 2000); })">Copy</button>
                <button class="close-details-btn" onclick="document.getElementById('flow-details-pane').classList.add('hidden'); document.querySelectorAll('.flow-step').forEach(s => s.classList.remove('selected')); document.querySelectorAll('.flow-arrow').forEach(a => a.classList.remove('path-selected'));">&times;</button>
            </div>
        </div>
        <div class="flow-details-content">
            <div class="json-viewer">${content}</div>
        </div>
    `;
  pane.classList.remove("hidden");
}
