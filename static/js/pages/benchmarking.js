import {
    createChart
} from '../shared/charts.js';
import { showNotification } from '../shared/utils.js';

// Configuration
const POLL_INTERVAL = 1000; // 1 second
const MAX_RETRIES = 60; // 1 minute timeout
let isScanning = false;
let activeIntervals = [];

// DOM Elements (declared at top level, initialized in initBenchmarking)
let runBtn, promptInput, resultsSection, progressModal, errorModal;
let steps = {};

// Initialize
export function initBenchmarking() {
    // Initialize DOM Elements
    runBtn = document.getElementById('run-benchmark-btn');
    promptInput = document.getElementById('benchmark-prompt');
    resultsSection = document.getElementById('results-section');
    progressModal = document.getElementById('progress-modal');
    errorModal = document.getElementById('error-modal');
    steps = {
        guardrails: document.getElementById('progress-guardrails'),
        azure: document.getElementById('progress-azure'),
        llmguard: document.getElementById('progress-llmguard')
    };

    if (!runBtn || !promptInput) return;

    // Quick Prompt Buttons
    document.querySelectorAll('.quick-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            promptInput.value = btn.dataset.prompt;
            updateCharCount();
        });
    });

    // Character Counter
    promptInput.addEventListener('input', updateCharCount);

    // Run Headline Benchmark
    runBtn.addEventListener('click', startBenchmark);

    // Close Modals
    document.getElementById('close-error-modal')?.addEventListener('click', () => {
        errorModal.classList.add('hidden');
    });

    document.getElementById('close-progress-modal')?.addEventListener('click', () => {
        progressModal.classList.add('hidden');
        resetProgressModal();
    });

    // Model Manager
    setupModelManager();

    // History — hero stats only; the inline table was removed (runs are viewable
    // on the Logs page). "View Scans History" is now a plain link to /logs.
    fetchHistory();

    // Clear Stats
    setupClearStats();

    // Click outside progress modal (requested: "click outside")
    progressModal?.addEventListener('click', (e) => {
        if (e.target === progressModal && !isScanning) {
            progressModal.classList.add('hidden');
            resetProgressModal();
        }
    });
}

function updateCharCount() {
    const count = promptInput.value.length;
    document.getElementById('char-count').textContent = count;
}

async function startBenchmark() {
    const prompt = promptInput.value.trim();
    if (!prompt) {
        showError('Please enter a prompt to test.');
        return;
    }

    isScanning = true;
    progressModal.classList.remove('hidden');

    try {
        // Fetch settings and current toggles
        const configResp = await fetch('/api/settings');
        const config = await configResp.json();

        const useAzure = document.getElementById('azure-toggle')?.checked ?? false;
        const useLLMGuard = document.getElementById('llmguard-toggle')?.checked ?? false;

        resetProgressSteps(config, { useAzure, useLLMGuard });

        // Helper to run a scan
        const runScan = async (name, url, payloadKey, stepId) => {
            const start = Date.now();
            try {
                const res = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt: prompt })
                });
                const data = await res.json();
                markStepResult(stepId, data);
                return data;
            } catch (e) {
                const errorData = {
                    vendor: name,
                    error: e.message,
                    flagged: false,
                    execution_time: (Date.now() - start) / 1000
                };
                markStepResult(stepId, errorData);
                return errorData;
            }
        };

        const promises = [];
        // 1. AI Guardrails
        promises.push(runScan('AI Guardrails', '/api/scan/guardrails', 'prompt', 'guardrails'));

        // 2. Azure (if enabled)
        if (useAzure) {
            promises.push(runScan('Azure AI', '/api/scan/azure', 'prompt', 'azure'));
        }

        // 3. LLM Guard (if enabled)
        if (useLLMGuard) {
            promises.push(runScan('LLM Guard', '/api/scan/llmguard', 'prompt', 'llmguard'));
        }

        // Wait for all to finish
        const results = await Promise.all(promises);

        // Calculate progress completion
        updateProgress(100);
        showModalSummary();

        // Save consolidated log to DB
        await fetch('/api/benchmark/log', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                prompt: prompt,
                results: results
            })
        });

        fetchHistory();

    } catch (error) {
        progressModal.classList.add('hidden');
        showNotification(error.message, 'error');
    } finally {
        isScanning = false;
    }
}

function resetProgressSteps(config, toggles = {}) {
    resetProgressModal();

    Object.keys(steps).forEach(key => {
        const step = steps[key];
        step.className = 'progress-step';
        const indicator = step.querySelector('.step-indicator');
        const status = step.querySelector('.step-status');

        // Check configuration and user toggles
        const isConfigured = (key === 'guardrails' && config.DEMO_API_KEY) ||
            (key === 'azure' && config.AZURE_CONTENT_SAFETY_KEY) ||
            (key === 'llmguard'); // LLM Guard is local/built-in

        const isToggledOn = key === 'guardrails' || (key === 'azure' && toggles.useAzure) || (key === 'llmguard' && toggles.useLLMGuard);

        if (!isConfigured) {
            markStepStatus(key, 'Skipped (Not Configured)', 'disabled');
        } else if (!isToggledOn) {
            markStepStatus(key, 'Skipped (Disabled)', 'disabled');
        } else {
            indicator.className = 'step-indicator pending';
            status.textContent = 'Waiting...';
        }
    });

    // Reset Progress Bar and Spinner
    updateProgress(0);
    const ring = document.querySelector('.progress-ring-active');
    if (ring) ring.classList.remove('done');

    document.querySelector('.progress-header h3').textContent = 'Running Security Scans';
    document.querySelector('.progress-header p').textContent = 'Analyzing your prompt across multiple vendors...';
    document.getElementById('modal-results-summary').classList.add('hidden');
}

function updateProgress(percent) {
    const barFill = document.getElementById('progress-bar-fill');
    const percentageText = document.getElementById('progress-percentage');
    const ring = document.querySelector('.progress-ring-active');

    barFill.style.width = `${percent}%`;
    percentageText.textContent = `${percent}%`;

    if (!ring) return;

    // Update circular progress
    const radius = ring.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (percent / 100) * circumference;
    ring.style.strokeDashoffset = offset;

    if (percent >= 100) {
        ring.classList.add('done');
    } else {
        ring.classList.remove('done');
    }
}

// function animateProgress removed

function markStepResult(vendorKey, result) {
    if (!result || result.error === "Missing API Key/Endpoint" || result.error?.includes("not configured")) {
        markStepStatus(vendorKey, 'Skipped', 'disabled');
        return;
    }

    if (result.error) {
        markStepStatus(vendorKey, `Failed: ${result.error}`, 'error');
        showNotification(`Vendor ${vendorKey} failed: ${result.error}`, 'warning');
    } else {
        const timeStr = result.execution_time ? `(${result.execution_time}s)` : '';
        markStepStatus(vendorKey, `Completed ${timeStr}`, 'success');

        // Make step clickable for details (requested: "once an item is done scanning we make it clickable")
        const step = steps[vendorKey];
        if (step) {
            step.classList.add('clickable');
            step.title = "Click to view JSON details";
            step.onclick = (e) => {
                e.stopPropagation();
                // Pass a mock "item" that openDetailModal expects
                openDetailModal({
                    prompt: promptInput.value,
                    results: [result] // Only show this vendor's details
                });
            };
        }
    }
}

function markStepStatus(vendor, statusText, type = 'pending') {
    const step = steps[vendor];
    if (!step) return;

    const indicator = step.querySelector('.step-indicator');
    const status = step.querySelector('.step-status');

    indicator.className = 'step-indicator';
    step.className = 'progress-step';

    if (type === 'success') {
        indicator.classList.add('success');
        step.classList.add('completed');
    } else if (type === 'error') {
        indicator.classList.add('error');
        step.classList.add('error');
    } else if (type === 'disabled') {
        step.classList.add('disabled');
        indicator.classList.add('disabled');
    } else {
        indicator.classList.add('pending');
    }

    status.textContent = statusText;
}

function showModalSummary() {
    const summaryGrid = document.getElementById('modal-summary-grid');
    summaryGrid.innerHTML = '';
    document.getElementById('modal-results-summary').classList.remove('hidden');

    const headerTitle = document.querySelector('.progress-header h3');
    const headerDesc = document.querySelector('.progress-header p');
    const iconContainer = document.querySelector('.progress-icon');

    headerTitle.textContent = 'Benchmark Complete';
    headerDesc.textContent = 'Security scans finished. Review findings below.';

    iconContainer.innerHTML = `
        <div class="success-checkmark-large">
            <svg viewBox="0 0 50 50" width="60" height="60">
                <circle cx="25" cy="25" r="22" fill="#22c55e" />
                <path d="M15 25 L22 32 L35 18" fill="none" stroke="white" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
        </div>
    `;
}

function resetProgressModal() {
    // Restore spinner icon for next run
    const iconContainer = document.querySelector('.progress-icon');
    iconContainer.innerHTML = `
        <svg viewBox="0 0 50 50" width="60" height="60">
            <circle class="progress-ring" cx="25" cy="25" r="20" fill="none" stroke="rgba(96, 165, 250, 0.2)" stroke-width="4"/>
            <circle class="progress-ring-active" cx="25" cy="25" r="20" fill="none" stroke="#3b82f6" stroke-width="4" stroke-linecap="round" stroke-dasharray="125.6" stroke-dashoffset="125.6"/>
        </svg>
    `;
    updateProgress(0);

    // Clear clickable states
    Object.values(steps).forEach(step => {
        step.classList.remove('clickable');
        step.onclick = null;
        step.title = "";
    });
}

// --- RESULTS & HISTORY ---

// displayResults function removed (latest result section is gone)
function displayResults(data) {
    // Legacy function placeholder
}

function addHistoryRow(item, prepend = false) {
    const tableBody = document.getElementById('benchmark-table-body');
    const row = document.createElement('tr');

    const results = item.results || item.result?.results || [];

    // Find vendor specific results
    const guardrails = results.find(r => r.vendor.includes('AI Guardrails'));
    const azure = results.find(r => r.vendor.includes('Azure'));
    const llmguard = results.find(r => r.vendor.includes('LLM Guard'));

    row.innerHTML = `
        <td class="time-cell">${formatTimeAgo(item.timestamp)}</td>
        <td class="prompt-cell" title="${escapeHtml(item.prompt)}">${escapeHtml(item.prompt)}</td>
        <td>${getStatusCell(guardrails)}</td>
        <td>${getStatusCell(azure)}</td>
        <td>${getStatusCell(llmguard)}</td>
        <td>
            <button class="action-btn view-details-btn">View Details</button>
        </td>
    `;

    // Attach click event for details
    row.querySelector('.view-details-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        openDetailModal(item);
    });

    // Allow clicking the row too
    row.addEventListener('click', () => {
        openDetailModal(item);
    });
    row.style.cursor = 'pointer';

    if (prepend) {
        // Remove empty state if present
        if (tableBody.querySelector('.no-history-row')) {
            tableBody.innerHTML = '';
        }
        tableBody.prepend(row);
    } else {
        tableBody.appendChild(row);
    }
}

function getStatusCell(result) {
    if (!result || result.error === "Missing API Key/Endpoint" || result.error?.includes("not configured")) {
        return `<span class="status-cell skipped">Skipped</span>`;
    }

    if (result.error) {
        return `<span class="status-cell flagged" title="${escapeHtml(result.error)}">Error</span>`;
    }

    if (result.flagged) {
        return `<span class="status-cell flagged">Flagged</span>`;
    }

    return `<span class="status-cell safe">Safe</span>`;
}


// --- DETAIL MODAL ---

function openDetailModal(item) {
    const modal = document.getElementById('result-detail-modal');
    const promptEl = document.getElementById('detail-prompt');
    const gridEl = document.getElementById('detail-grid');

    if (!modal || !promptEl || !gridEl) return;

    // Reset content
    promptEl.textContent = item.prompt;
    gridEl.innerHTML = '';

    const results = item.results || item.result?.results || [];

    // Populate vendors
    results.forEach(res => {
        const card = document.createElement('div');
        card.className = 'vendor-detail-card';

        const timeStr = res.execution_time ? `${res.execution_time}s` : '--';
        let flaggedClass = res.flagged ? 'flagged' : 'safe';
        let statusText = res.flagged ? 'Risk Detected' : 'Passed & Safe';

        // Check for breakdown errors
        const hasErrors = res.breakdown?.some(b => b.error);
        if (hasErrors && !res.flagged) {
            flaggedClass = 'error'; // We will style .vd-status-large.error
            statusText = 'Completed with Errors';
        }

        // Breakdown badges
        let detailsHtml = '';

        // If we have a structured breakdown (LLM Guard), use table format
        if (res.breakdown && res.breakdown.length > 0) {
            const rows = res.breakdown.map(b => {
                let rowClass = 'good';
                let statusText = 'Pass';
                let scoreText = Math.round(b.score * 100) + '%';
                let tooltip = '';

                if (b.error) {
                    rowClass = 'error';
                    statusText = 'Error';
                    scoreText = '--';
                    tooltip = escapeHtml(b.error);
                } else if (b.detected) {
                    rowClass = 'bad';
                    statusText = 'Flagged';
                }

                return `
                <div class="breakdown-row ${rowClass}" title="${tooltip}">
                    <span class="bd-type">${escapeHtml(b.detector_type)}</span>
                    <span class="bd-model">${escapeHtml(b.model || 'default')}</span>
                    <span class="bd-score">${scoreText}</span>
                    <span class="bd-status">${statusText}</span>
                </div>
                `;
            }).join('');

            detailsHtml = `
                <div class="breakdown-table">
                    <div class="breakdown-header">
                        <span>Scanner</span>
                        <span>Model</span>
                        <span>Risk</span>
                        <span>Status</span>
                    </div>
                    ${rows}
                </div>
            `;
        } else if (res.details && res.details.length > 0) {
            detailsHtml = res.details.map(d => `<span class="vd-badge">${escapeHtml(d)}</span>`).join('');
        }

        // JSON Dump
        const jsonId = `json-${Math.random().toString(36).substr(2, 9)}`;

        card.innerHTML = `
            <div class="vd-header">
                <div class="vd-vendor-info">
                    <span class="vd-vendor-name">${res.vendor}</span>
                    <span class="vd-time">⏱ ${timeStr}</span>
                </div>
                <span class="vd-status-large ${flaggedClass}">
                    ${statusText}
                </span>
            </div>
            
            <div class="vd-breakdown">
                ${detailsHtml}
            </div>

            <div class="vd-json-section">
                <button class="toggle-reports-btn" onclick="toggleJsonDetail('${jsonId}')">
                    <span>View Raw JSON Response</span>
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </button>
                 <div id="${jsonId}-json" class="raw-reports-content hidden">
                    <div class="raw-report-item">
                        <div class="raw-report-body">${JSON.stringify(res.raw_response || res, null, 2)}</div>
                    </div>
                </div>
            </div>
        `;

        gridEl.appendChild(card);
    });

    modal.classList.remove('hidden');
}

// Global Toggle for Details Modal JSON
window.toggleJsonDetail = (id) => {
    // If ID ends with -json, strip it (compatibility with old logic)
    const containerId = id.endsWith('-json') ? id : `${id}-json`;
    const container = document.getElementById(containerId);

    if (container) {
        container.classList.toggle('hidden');
    }
};

// Close Detail Modal logic
document.getElementById('close-detail-modal')?.addEventListener('click', () => {
    document.getElementById('result-detail-modal').classList.add('hidden');
});

// Click outside to close detail modal
document.getElementById('result-detail-modal')?.addEventListener('click', (e) => {
    if (e.target === document.getElementById('result-detail-modal')) {
        document.getElementById('result-detail-modal').classList.add('hidden');
    }
});


function showError(msg) {
    showNotification(msg, 'error');
}


// --- HISTORY & UTILS ---

async function fetchHistory() {
    try {
        const response = await fetch('/api/benchmark/history');
        if (response.ok) {
            const history = await response.json();
            renderHistoryTable(history);
        }
    } catch (e) {
        console.error('Failed to fetch history:', e);
    }
}

function renderHistoryTable(history) {
    // Hero stats update regardless of whether the (removed) table exists.
    updateHeroStats(history || []);

    const tableBody = document.getElementById('benchmark-table-body');
    if (!tableBody) return;
    tableBody.innerHTML = '';

    if (!history || history.length === 0) {
        tableBody.innerHTML = '<tr class="no-history-row"><td colspan="6">No benchmark runs recorded yet.</td></tr>';
        return;
    }

    // Populate table
    history.forEach(item => {
        addHistoryRow(item);
    });
}

function updateHeroStats(history) {
    const statTotal = document.getElementById('stat-total-scans');
    const statThreats = document.getElementById('stat-threats-detected');
    const statTime = document.getElementById('stat-avg-time');

    if (!statTotal || !statThreats || !statTime) {
        console.warn('Hero stats elements not found');
        return;
    }

    console.log('[DEBUG] Updating Hero Stats with history length:', history?.length || 0);

    const totalScans = history?.length || 0;
    let threatsFound = 0;
    let totalTime = 0;
    let timeCount = 0;

    if (Array.isArray(history)) {
        history.forEach((item, idx) => {
            const results = item.results || item.result?.results || [];
            if (!Array.isArray(results)) {
                return;
            }

            if (results.some(r => r && (r.flagged === true || r.flagged === 1 || String(r.flagged).toLowerCase() === 'true'))) {
                threatsFound++;
            }
            results.forEach(r => {
                if (r && r.execution_time) {
                    const time = parseFloat(r.execution_time);
                    if (!isNaN(time)) {
                        totalTime += time;
                        timeCount++;
                    }
                }
            });
        });
    }

    const avgTime = timeCount > 0 ? (totalTime / timeCount).toFixed(2) + 's' : '--';

    console.log(`[DEBUG] Calculated stats: scans=${totalScans}, threats=${threatsFound}, avgTime=${avgTime}`);

    statTotal.textContent = totalScans;
    statThreats.textContent = threatsFound;
    statTime.textContent = avgTime;
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .substring(0, 50) + (text.length > 50 ? '...' : '');
}

function formatTimeAgo(timestampStr) {
    const date = new Date(timestampStr);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000); // seconds

    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
}

function getBadgesHtml(results) {
    if (!results) return '';
    // Count flagged vs total
    const flagged = results.filter(r => r.flagged).length;
    if (flagged > 0) {
        return `<span class="h-badge danger">${flagged} Flagged</span>`;
    }
    return `<span class="h-badge success">All Safe</span>`;
}

function loadHistoryItem(item) {
    // Populate input
    promptInput.value = item.prompt;
    updateCharCount();

    const results = item.results || item.result?.results || [];

    // Show results immediately
    displayResults({
        prompt: item.prompt,
        results: results
    });
}

// Model Manager (Simplified for restoration)
function setupModelManager() {
    const modal = document.getElementById('model-manager-modal');
    const openBtn = document.getElementById('open-model-manager');
    const closeBtn = document.getElementById('close-model-manager');
    const saveBtn = document.getElementById('save-models-btn');

    if (openBtn) openBtn.addEventListener('click', () => {
        modal.classList.remove('hidden');
        loadModels();
    });

    if (closeBtn) closeBtn.addEventListener('click', () => {
        modal.classList.add('hidden');
    });

    if (saveBtn) saveBtn.addEventListener('click', () => {
        modal.classList.add('hidden');
        if (window.showNotification) {
            window.showNotification('Settings saved successfully', 'success');
        }
    });

    // Click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
        }
    });
}

async function loadModels() {
    const container = document.getElementById('model-list-container');
    container.innerHTML = '<div class="loading-models">Loading...</div>';

    try {
        const resp = await fetch('/api/models/status');
        const models = await resp.json();
        renderModels(models);
    } catch (e) {
        container.innerHTML = '<div class="error">Failed to load models</div>';
    }
}

function renderModels(models) {
    const container = document.getElementById('model-list-container');
    container.innerHTML = '';

    // Group models
    const groups = {
        'PromptInjection': {
            title: 'Injection Detection',
            desc: 'Detects prompt injection attacks. Standard (best) or Tiny (fast). Only one can be active.',
            items: []
        },
        'Utilities': {
            title: 'Additional Scanners',
            desc: 'Supplementary safety checks for content filtering.',
            items: []
        }
    };

    models.forEach(model => {
        if (model.parent_key === 'PromptInjection' || model.id === 'PromptInjection' || model.id === 'deberta-v3-base') {
            groups['PromptInjection'].items.push(model);
        } else {
            groups['Utilities'].items.push(model);
        }
    });

    // Render groups
    Object.keys(groups).forEach(key => {
        const group = groups[key];
        if (group.items.length === 0) return;

        const groupEl = document.createElement('div');
        groupEl.className = 'mm-group';
        groupEl.innerHTML = `
            <div class="mm-group-title">${group.title}</div>
            <div class="mm-group-desc">${group.desc}</div>
            <div class="mm-group-list"></div>
        `;

        const listEl = groupEl.querySelector('.mm-group-list');
        group.items.forEach(model => {
            const itemEl = document.createElement('div');
            itemEl.className = 'mm-model-item';
            const isSelected = model.active;

            itemEl.innerHTML = `
                <div class="mm-model-info">
                    <div class="mm-model-name">
                        ${model.name}
                        ${model.size ? `<span class="mm-model-size">${model.size}</span>` : ''}
                    </div>
                    <div class="mm-model-desc">${model.description}</div>
                </div>
                <div class="mm-model-actions">
                    ${model.downloaded ? `
                        <label class="mm-toggle" title="${isSelected ? 'Disable' : 'Enable'} model">
                            <input type="checkbox" class="model-toggle" 
                                data-id="${model.id}" 
                                data-parent="${model.parent_key || (key === 'PromptInjection' ? 'PromptInjection' : '')}"
                                ${isSelected ? 'checked' : ''}>
                            <span class="mm-slider"></span>
                        </label>
                    ` : `
                        <button class="mm-model-btn download" data-id="${model.id}">Download</button>
                    `}
                </div>
            `;
            listEl.appendChild(itemEl);
        });

        container.appendChild(groupEl);
    });

    // Add Listeners
    container.querySelectorAll('.model-toggle').forEach(toggle => {
        toggle.addEventListener('change', async (e) => {
            const modelId = e.target.dataset.id;
            const parent = e.target.dataset.parent;
            const enabled = e.target.checked;

            // Handle mutual exclusivity for PromptInjection in UI
            if (parent === 'PromptInjection' && enabled) {
                container.querySelectorAll(`.model-toggle[data-parent="PromptInjection"]`).forEach(t => {
                    if (t !== e.target) t.checked = false;
                });
            }

            await toggleModel(modelId, enabled);
        });
    });

    container.querySelectorAll('.download').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const modelId = e.target.dataset.id;
            await downloadModel(modelId, e.target);
        });
    });
}

async function toggleModel(id, enabled) {
    try {
        const response = await fetch('/api/models/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, enabled })
        });

        if (!response.ok) throw new Error('Failed to toggle model');

        const result = await response.json();
        console.log('Model toggled:', result);

        // Update model tag in sidebar if it's a main model
        if (id === 'PromptInjection' || id === 'deberta-v3-base') {
            const tag = document.getElementById('llm-guard-model-tag');
            if (tag) {
                if (result.active_models.length > 0) {
                    tag.textContent = id.includes('tiny') ? 'Tiny' : 'Standard';
                }
            }
        }
    } catch (e) {
        console.error(e);
        showNotification('Failed to update model status', 'error');
    }
}

async function downloadModel(id, btn) {
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Downloading...';

    try {
        const response = await fetch('/api/models/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });

        if (!response.ok) throw new Error('Download failed');

        showNotification('Model downloaded successfully', 'success');
        loadModels(); // Refresh list
    } catch (e) {
        console.error(e);
        btn.disabled = false;
        btn.textContent = originalText;
        showNotification('Model download failed', 'error');
    }
}



function setupClearStats() {
    const btn = document.getElementById('clear-all-btn');
    const historyBtn = document.getElementById('clear-history-btn');
    const confirmModal = document.getElementById('confirm-clear-modal');
    const confirmYes = document.getElementById('confirm-clear-yes');
    const confirmNo = document.getElementById('confirm-clear-cancel');

    const showConfirm = () => {
        if (confirmModal) confirmModal.classList.remove('hidden');
    };

    const hideConfirm = () => {
        if (confirmModal) confirmModal.classList.add('hidden');
    };

    const handleClear = async () => {
        hideConfirm();
        try {
            const response = await fetch('/api/benchmark/clear', {
                method: 'POST'
            });
            if (response.ok) {
                if (window.showNotification) {
                    window.showNotification('Benchmark history cleared', 'success');
                }
                // Wait a tiny bit for DB to settle
                setTimeout(() => {
                    if (typeof fetchHistory === 'function') {
                        fetchHistory();
                    }
                }, 100);
            } else {
                const errData = await response.json().catch(() => ({}));
                console.error('Clear failed:', errData);
                if (window.showNotification) {
                    window.showNotification('Failed to clear history', 'error');
                }
            }
        } catch (e) {
            console.error('Clear error:', e);
            if (e.name !== 'AbortError') {
                showNotification('Error clearing history', 'error');
            }
        }
    };

    if (btn) btn.addEventListener('click', showConfirm);
    if (historyBtn) historyBtn.addEventListener('click', showConfirm);
    if (confirmNo) confirmNo.addEventListener('click', hideConfirm);
    if (confirmYes) confirmYes.addEventListener('click', handleClear);

    // Click outside to close
    confirmModal?.addEventListener('click', (e) => {
        if (e.target === confirmModal) hideConfirm();
    });
}
