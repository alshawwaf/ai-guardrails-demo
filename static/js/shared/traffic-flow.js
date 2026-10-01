// ============================================
// Traffic Flow Visualization Module
// All server / prompt / LLM data is rendered with textContent or DOM
// construction. Colours come from the fixed palette in utils.js.
// ============================================

import { getAttackColor, getDetectorInfo } from "./utils.js";
import { renderScanPipeline, renderScanningPipeline } from "./pipeline.js";

// Small element helper: el("span", "cls", "text")
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

/**
 * Fill the compact modal header (status badge + optional model badge + close).
 * statusColor must be a fixed value chosen by this module, never data.
 */
function renderCompactHeader(modalHeader, { headerClass, statusColor, statusIcon, statusText, modelText }) {
  modalHeader.className = `modal-header compact-header ${headerClass}`;
  const left = el("div", "compact-header-left");
  const badge = el("span", "compact-status-badge");
  badge.style.setProperty("--status-color", statusColor);
  badge.append(el("span", "status-icon", statusIcon), el("span", "status-text", statusText));
  left.appendChild(badge);
  if (modelText) left.appendChild(el("span", "compact-model-badge", modelText));
  const closeBtn = el("button", "close-modal-btn", "×");
  closeBtn.id = "close-result-modal";
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Close");
  modalHeader.replaceChildren(left, closeBtn);
}

// guardrails_error may be a string or {status, error|message, request_id}.
function formatGuardrailsError(err) {
  if (!err) return "";
  if (typeof err === "string") return err;
  if (typeof err !== "object") return String(err);
  const parts = [];
  if (err.status != null) parts.push(`HTTP ${err.status}`);
  const msg = err.error || err.message;
  if (msg) parts.push(typeof msg === "string" ? msg : JSON.stringify(msg));
  if (err.request_id) parts.push(`request ${err.request_id}`);
  return parts.length ? parts.join(" · ") : JSON.stringify(err);
}

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
  if (flagsContainer) flagsContainer.replaceChildren();
  if (statsContainer) statsContainer.replaceChildren();
  if (modalHeader) {
    renderCompactHeader(modalHeader, {
      headerClass: "neutral", statusColor: "#7c3aed", statusIcon: "⏳", statusText: "Scanning…",
    });
  }
  const card = el("div", "modal-card compact-flow-card");
  card.appendChild(renderScanningPipeline({ useInbound, useOutbound, provider, model }));
  if (flagsContainer) flagsContainer.appendChild(card);
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
  flagsContainer.replaceChildren();
  if (statsContainer) statsContainer.replaceChildren();

  if (data.isComparison) {
    // --- Comparison View Logic ---
    renderCompactHeader(modalHeader, {
      headerClass: "neutral",
      statusColor: "var(--primary-color)",
      statusIcon: "📊",
      statusText: "Market Comparison",
      modelText: "AI Guardrails vs Competitors",
    });

    const comparisonContainer = el("div", "comparison-view");

    // Chart Section
    const chartCard = el("div", "modal-card comparison-chart-card");
    const canvas = document.createElement("canvas");
    canvas.id = "comparison-chart";
    canvas.height = 150;
    chartCard.appendChild(canvas);
    comparisonContainer.appendChild(chartCard);

    // Vendor Details Section
    const vendorGrid = el("div", "vendor-comparison-grid");
    const results = Array.isArray(data.results) ? data.results : [];

    results.forEach(res => {
      const isError = !!res.error;
      const vendorClass = isError ? 'error' : (res.flagged ? 'flagged' : 'safe');
      const vendorCard = el("div", `vendor-card ${vendorClass}`);

      const statusColor = isError ? "#f97316" : (res.flagged ? "#ef4444" : "#22c55e");
      const statusIcon = isError ? "⚠️" : (res.flagged ? "⛔" : "✓");
      const score = Number(res.score);
      const width = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;

      const info = el("div", "vendor-info");
      const header = el("div", "vendor-header");
      header.appendChild(el("span", "vendor-name", res.vendor));
      const status = el("span", "vendor-status", statusIcon);
      status.style.color = statusColor;
      header.appendChild(status);

      const bar = el("div", "vendor-score-bar");
      const fill = el("div", "score-fill");
      fill.style.width = `${width}%`;
      fill.style.background = statusColor;
      bar.appendChild(fill);

      const scoreText = el("div", "vendor-score-text",
        isError ? "Service Error" : `${res.score}% Threat Confidence`);

      const details = el("div", "vendor-details");
      if (Array.isArray(res.details) && res.details.length > 0) {
        res.details.forEach(d => details.appendChild(el("span", "detail-pill", d)));
      } else {
        details.appendChild(el("span", "detail-pill", "No threats detected"));
      }

      info.append(header, bar, scoreText, details);
      vendorCard.appendChild(info);
      vendorGrid.appendChild(vendorCard);
    });

    comparisonContainer.appendChild(vendorGrid);
    flagsContainer.appendChild(comparisonContainer);

    // Initialize Chart (wait for DOM)
    setTimeout(() => {
      const chartCanvas = document.getElementById('comparison-chart');
      if (!chartCanvas || typeof Chart === "undefined") return;

      const ctx = chartCanvas.getContext('2d');
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: results.map(r => String(r.vendor == null ? "" : r.vendor)),
          datasets: [{
            label: 'Threat Confidence Score',
            data: results.map(r => Number(r.score) || 0),
            backgroundColor: results.map(r => r.flagged ? 'rgba(239, 68, 68, 0.7)' : 'rgba(34, 197, 94, 0.7)'),
            borderColor: results.map(r => r.flagged ? '#ef4444' : '#22c55e'),
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
    const inboundError = formatGuardrailsError(data.guardrails_error);
    // /api/analyze answers 502 with guardrails_outbound_error when the reply
    // could not be scanned (the reply is withheld): a failure, never "Safe".
    const outboundError = !guardrailsOutboundResult
      ? formatGuardrailsError(data.guardrails_outbound_error)
      : "";
    const guardError = inboundError || outboundError;
    // Any other failed request (request_failed is set by the batch runner).
    const requestError = !inboundError && !outboundError && (data.request_failed || (data.error && !data.openai_response))
      ? String(data.error || (data.http_status ? `HTTP ${data.http_status}` : "Request failed"))
      : "";

    let headerClass, statusIcon, statusText, statusColor;

    if (!guardrailsResult && inboundError) {
      headerClass = "warning";
      statusIcon = "⚠️";
      statusText = "Scan Failed";
      statusColor = "#f97316";
    } else if (outboundError) {
      headerClass = "warning";
      statusIcon = "⚠️";
      statusText = "Outbound Scan Failed";
      statusColor = "#f97316";
    } else if (requestError) {
      headerClass = "warning";
      statusIcon = "⚠️";
      statusText = "Request Failed";
      statusColor = "#f97316";
    } else if (!guardrailsResult) {
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

    renderCompactHeader(modalHeader, { headerClass, statusColor, statusIcon, statusText, modelText: modelDisplay });

    const flowCard = el("div", "modal-card compact-flow-card");

    // Scan toggles live on the playground; elsewhere infer from the result.
    const inCb = document.getElementById("guardrails-scan-checkbox");
    const outCb = document.getElementById("guardrails-outbound-checkbox");
    const useGuardrails = inCb ? inCb.checked : !!guardrailsResult;
    const useGuardrailsOutbound = outCb ? outCb.checked : !!guardrailsOutboundResult;

    const flowDiagram = renderTrafficFlow(data, useGuardrails, useGuardrailsOutbound);
    flowDiagram.classList.add("modal-pipeline");
    flowCard.appendChild(flowDiagram);
    flagsContainer.appendChild(flowCard);

    if (guardError) {
      const errSection = el("div", "compact-threat-section");
      errSection.appendChild(el("span", "threat-section-label",
        outboundError && !inboundError ? "Outbound guard error:" : "Guard error:"));
      errSection.appendChild(el("span", "compact-guard-error", guardError));
      flagsContainer.appendChild(errSection);
      if (outboundError && !inboundError) {
        const note = el("div", "compact-threat-section");
        note.appendChild(el("span", "compact-guard-error",
          "The model replied, but the reply could not be scanned, so it was withheld."));
        flagsContainer.appendChild(note);
      }
    } else if (requestError) {
      const errSection = el("div", "compact-threat-section");
      errSection.appendChild(el("span", "threat-section-label", "Error:"));
      errSection.appendChild(el("span", "compact-guard-error", requestError));
      flagsContainer.appendChild(errSection);
    }

    // Keep the full detector_type (e.g. "moderated_content/hate") so labels keep
    // their category; fall back to the short attack_vectors list.
    const detectedTypes = (result) => {
      const out = [];
      if (result && Array.isArray(result.breakdown)) {
        result.breakdown.forEach((r) => {
          if (r && r.detected && r.detector_type) {
            const t = String(r.detector_type);
            if (!out.includes(t)) out.push(t);
          }
        });
      }
      if (out.length === 0 && result && Array.isArray(result.attack_vectors)) {
        result.attack_vectors.forEach((v) => { if (v && !out.includes(String(v))) out.push(String(v)); });
      }
      return out;
    };
    const inboundVectors = detectedTypes(guardrailsResult);
    const outboundVectors = detectedTypes(guardrailsOutboundResult);

    if (inboundVectors.length > 0 || outboundVectors.length > 0) {
      const threatSection = el("div", "compact-threat-section");
      threatSection.appendChild(el("span", "threat-section-label", "Detected:"));

      const pillContainer = el("div", "threat-pills");

      [...inboundVectors, ...outboundVectors].forEach((vector) => {
        const info = getDetectorInfo(vector);
        const pill = el("span", "threat-pill", info.label);
        if (info.label !== info.type) pill.title = info.type;
        pill.style.setProperty("--pill-color", getAttackColor(vector));
        pillContainer.appendChild(pill);
      });

      threatSection.appendChild(pillContainer);
      flagsContainer.appendChild(threatSection);
    }

    const detailsPane = el("div", "hidden");
    detailsPane.id = "flow-details-pane";
    flagsContainer.appendChild(detailsPane);

    if (data.openai_response) {
      const responseSection = el("div", "compact-response-section");

      const responseHeader = el("div", "response-header");
      responseHeader.appendChild(el("span", "response-label", `${providerLabel} Response`));
      responseSection.appendChild(responseHeader);

      const responseBox = el("div", "compact-response-box", data.openai_response);
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
 * Create attack card element (legacy, currently unused)
 * @param {string} vector - Attack vector name
 * @returns {HTMLElement} Card element
 */
function createAttackCard(vector) {
  const card = el("div", "attack-type-card");
  card.style.display = "flex";
  card.style.flexDirection = "row";
  card.style.alignItems = "center";

  const color = getAttackColor(vector);

  card.style.setProperty("--attack-color", color);
  card.style.background = `${color}15`;
  card.style.borderColor = `${color}40`;
  card.style.borderLeft = `3px solid ${color}`;

  const name = el("span", "attack-name", getDetectorInfo(vector).label);
  name.style.marginLeft = "0";
  card.appendChild(name);
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
        : (data.guardrails_error ? formatGuardrailsError(data.guardrails_error) : "No scan performed.");
      break;
    case "llm":
      if (data.model_provider === "azure") {
        title = "Azure OpenAI Response";
      } else if (data.model_provider === "gemini") {
        title = "Google Gemini Response";
      } else if (data.model_provider === "anthropic") {
        title = "Anthropic Claude Response";
      } else if (data.model_provider === "ollama") {
        title = "Ollama Response";
      } else {
        title = "OpenAI Response";
      }
      content = data.openai_response
        || (data.guardrails_outbound_error
          ? "The model replied, but the reply was withheld because the outbound scan failed."
          : "No response generated.");
      break;
    case "outbound":
      title = "Demo Outbound Scan";
      content = data.guardrails_outbound_result
        ? JSON.stringify(data.guardrails_outbound_result, null, 2)
        : (data.guardrails_outbound_error
          ? formatGuardrailsError(data.guardrails_outbound_error)
          : "No scan performed.");
      break;
    case "deliver":
    case "user-response":
      title = "Response Delivered to User";
      content =
        data.openai_response ||
        "No response was delivered (blocked or not generated).";
      break;
  }

  const header = el("div", "flow-details-header");
  header.appendChild(el("div", "flow-details-title", title));

  const actions = el("div");
  actions.style.display = "flex";
  actions.style.gap = "0.5rem";
  actions.style.alignItems = "center";

  const viewer = el("div", "json-viewer", content);

  const copyBtn = el("button", "copy-btn", "Copy");
  copyBtn.type = "button";
  copyBtn.addEventListener("click", () => {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(viewer.textContent).then(() => {
      copyBtn.textContent = "Copied!";
      setTimeout(() => { copyBtn.textContent = "Copy"; }, 2000);
    }).catch(() => {});
  });

  const closeBtn = el("button", "close-details-btn", "×");
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Close");
  closeBtn.addEventListener("click", () => {
    pane.classList.add("hidden");
    document.querySelectorAll(".flow-step").forEach((s) => s.classList.remove("selected"));
    document.querySelectorAll(".flow-arrow").forEach((a) => a.classList.remove("path-selected"));
  });

  actions.append(copyBtn, closeBtn);
  header.appendChild(actions);

  const body = el("div", "flow-details-content");
  body.appendChild(viewer);

  pane.replaceChildren(header, body);
  pane.classList.remove("hidden");
}
