// ============================================
// Playground Page Module
// ============================================

import { setLoading, showNotification } from '../shared/utils.js';
import { displayResults, showScanning } from '../shared/traffic-flow.js';
import { initHeroPipeline } from '../shared/pipeline.js';

/**
 * Initialize playground page
 */
export function initPlayground() {
    // Interactive "how Guard works" pipeline at the top of the page.
    initHeroPipeline(document.getElementById("guard-pipeline"));

    const promptInput = document.getElementById("prompt");
    const analyzeBtn = document.getElementById("analyze-btn");
    const resultsSection = document.getElementById("results-section");
    const charCount = document.querySelector(".char-count");
    const examplesContainer = document.getElementById("examples-container");
    const providerSelect = document.getElementById("provider-select");
    const modelSelect = document.getElementById("model-select"); // original hidden select
    const modelWrapper = document.getElementById("model-select-wrapper");
    const modelTrigger = document.getElementById("model-select-trigger");
    const modelDropdown = document.getElementById("model-dropdown-list");
    const modelOptions = document.getElementById("model-options");
    const modelSearchInput = document.getElementById("model-search");
    const selectedModelText = document.getElementById("selected-model-text");

    const setDefaultBtn = document.getElementById("set-default-btn");

    // Helper to toggle dropdown
    function toggleDropdown(show) {
        if (!modelWrapper || !modelDropdown) return;
        if (show === undefined) show = modelDropdown.classList.contains("hidden");
        
        if (show) {
            modelDropdown.classList.remove("hidden");
            modelWrapper.classList.add("open");
            if (modelSearchInput) {
                modelSearchInput.value = "";
                filterOptions("");
                setTimeout(() => modelSearchInput.focus(), 10);
            }
        } else {
            modelDropdown.classList.add("hidden");
            modelWrapper.classList.remove("open");
        }
    }

    // Filter options
    function filterOptions(term) {
        if (!modelOptions) return;
        const options = modelOptions.querySelectorAll(".option-item");
        let visibleCount = 0;
        
        options.forEach(opt => {
            const matches = opt.dataset.value.toLowerCase().includes(term.toLowerCase());
            opt.classList.toggle("hidden", !matches);
            if (matches) visibleCount++;
        });

        // Add "no results" if needed
        let noRes = modelOptions.querySelector(".no-results");
        if (visibleCount === 0) {
            if (!noRes) {
                noRes = document.createElement("div");
                noRes.className = "no-results";
                noRes.textContent = "No models match your search";
                modelOptions.appendChild(noRes);
            }
            noRes.classList.remove("hidden");
        } else if (noRes) {
            noRes.classList.add("hidden");
        }
    }

    // Inline, actionable hint shown next to the model selector when Ollama is
    // selected but no models came back (server couldn't reach the model host).
    // Kept minimal: a short message + Retry (reload re-queries Ollama) + a link
    // to Settings to check the API URL.
    function setOllamaHint(show) {
        const row = modelWrapper ? modelWrapper.closest(".cp2-model-row") : null;
        let hint = document.getElementById("ollama-connection-hint");
        if (!show) {
            if (hint) hint.remove();
            return;
        }
        if (!row) return;
        if (!hint) {
            hint = document.createElement("div");
            hint.id = "ollama-connection-hint";
            hint.className = "cp2-model-hint";
            hint.innerHTML =
                `<span>Can't reach Ollama — check the model server / ` +
                `<a href="/settings">Settings</a>.</span>` +
                `<button type="button" id="ollama-retry-btn" class="cp2-model-hint-retry">Retry</button>`;
            // Place the hint directly under the model row.
            row.insertAdjacentElement("afterend", hint);
            const retry = hint.querySelector("#ollama-retry-btn");
            if (retry) retry.addEventListener("click", () => window.location.reload());
        }
    }

    // Populate models
    function populateModels() {
        if (!providerSelect || !modelOptions || !window.llmData) return;

        const provider = providerSelect.value;
        const data = window.llmData[provider];

        modelOptions.innerHTML = "";
        selectedModelText.textContent = "Select a model...";
        setOllamaHint(false);

        if (provider === 'azure') {
            const modelName = data.deployment;
            addOption(modelName);
            updateSelection(modelName);
            modelWrapper.style.pointerEvents = "none";
            modelWrapper.style.opacity = "0.7";
        } else {
            modelWrapper.style.pointerEvents = "auto";
            modelWrapper.style.opacity = "1";

            if (Array.isArray(data) && data.length > 0) {
                data.forEach(model => addOption(model));

                // Selection logic logic
                const savedModel = localStorage.getItem("default_model");
                let targetModel = data[0];

                if (provider === 'openai' && data.includes('gpt-3.5-turbo')) {
                    targetModel = 'gpt-3.5-turbo';
                } else if (provider === 'gemini' && data.includes('gemini-flash-lite-latest')) {
                    targetModel = 'gemini-flash-lite-latest';
                } else if (savedModel && data.includes(savedModel)) {
                    targetModel = savedModel;
                }
                
                updateSelection(targetModel);
            } else {
                selectedModelText.textContent = provider === 'ollama' ? "No connection" : "No models available";
                modelWrapper.style.pointerEvents = "none";
                modelWrapper.style.opacity = "0.7";
                if (provider === 'ollama') setOllamaHint(true);
            }
        }
    }

    function addOption(value) {
        const div = document.createElement("div");
        div.className = "option-item";
        div.textContent = value;
        div.dataset.value = value;
        div.onclick = (e) => {
            e.stopPropagation();
            updateSelection(value);
            toggleDropdown(false);
        };
        modelOptions.appendChild(div);
    }

    function updateSelection(value) {
        if (!modelSelect || !selectedModelText) return;
        modelSelect.value = value;
        selectedModelText.textContent = value;

        // Highlight in list
        modelOptions.querySelectorAll(".option-item").forEach(opt => {
            opt.classList.toggle("selected", opt.dataset.value === value);
        });
        refreshDefaultBtn();
    }

    // Reflect whether the current provider+model is the saved default, without
    // clobbering the button's icon (only the .cp2-default-text span changes).
    function refreshDefaultBtn() {
        if (!setDefaultBtn || !providerSelect) return;
        const isAzure = providerSelect.value === "azure";
        const isDefault =
            localStorage.getItem("default_provider") === providerSelect.value &&
            (isAzure || localStorage.getItem("default_model") === (modelSelect ? modelSelect.value : ""));
        setDefaultBtn.classList.toggle("is-default", isDefault);
        const txt = setDefaultBtn.querySelector(".cp2-default-text");
        if (txt) txt.textContent = isDefault ? "Default model" : "Set as default";
        const icon = setDefaultBtn.querySelector("svg");
        if (icon) icon.innerHTML = isDefault ? '<path d="M5 13l4 4L19 7"/>' : '<path d="M6 3h12v18l-6-4-6 4z"/>';
    }

    // Set up listeners
    if (modelTrigger) {
        modelTrigger.onclick = (e) => {
            e.stopPropagation();
            toggleDropdown();
        };
    }

    if (modelSearchInput) {
        modelSearchInput.onclick = (e) => e.stopPropagation();
        modelSearchInput.oninput = (e) => filterOptions(e.target.value);
    }

    // Close on click outside
    document.addEventListener("click", () => toggleDropdown(false));

    // Initial Load & Event Listeners
    if (providerSelect) {
        providerSelect.addEventListener("change", populateModels);
        
        // Fetch API settings to check configuration
        fetch("/api/settings")
            .then(res => res.json())
            .then(settings => {
                const guardrailsInbound = document.getElementById("guardrails-scan-checkbox");
                const guardrailsOutbound = document.getElementById("guardrails-outbound-checkbox");
                
                if (!settings.guardrails_configured) {
                    if (guardrailsInbound) {
                        guardrailsInbound.disabled = true;
                        guardrailsInbound.parentElement.title = "AI Guardrails API Key and Project ID required in Settings";
                        guardrailsInbound.parentElement.style.opacity = "0.5";
                        guardrailsInbound.parentElement.style.cursor = "not-allowed";
                    }
                    if (guardrailsOutbound) {
                        guardrailsOutbound.disabled = true;
                        guardrailsOutbound.parentElement.title = "AI Guardrails API Key and Project ID required in Settings";
                        guardrailsOutbound.parentElement.style.opacity = "0.5";
                        guardrailsOutbound.parentElement.style.cursor = "not-allowed";
                    }
                }
            })
            .catch(err => console.error("Error fetching settings:", err));

        // Load defaults
        const savedProvider = localStorage.getItem("default_provider");
        const savedModel = localStorage.getItem("default_model");

        if (savedProvider) {
            providerSelect.value = savedProvider;
            populateModels();

            // Only override if the provider isn't one of the 'forced default' ones
            const isForcedDefault = savedProvider === 'openai' || savedProvider === 'gemini';
            const availableModels = window.llmData[savedProvider];
            if (savedModel && providerSelect.value !== 'azure' && !isForcedDefault && Array.isArray(availableModels) && availableModels.includes(savedModel)) {
                updateSelection(savedModel);
            }
        } else {
            // No saved preference — fall back to the server-pinned default
            // (window.defaultProvider / window.defaultModel), else Azure.
            const dp = window.defaultProvider || "azure";
            providerSelect.value = dp;
            populateModels();
            const dm = window.defaultModel;
            const avail = window.llmData[dp];
            if (dm && dp !== 'azure' && Array.isArray(avail) && avail.includes(dm)) {
                updateSelection(dm);
            }
        }
    }

    // Set Default Button Handler
    if (setDefaultBtn && providerSelect && modelSelect) {
        setDefaultBtn.addEventListener("click", () => {
            localStorage.setItem("default_provider", providerSelect.value);
            if (providerSelect.value !== 'azure') {
                localStorage.setItem("default_model", modelSelect.value);
            }
            const txt = setDefaultBtn.querySelector(".cp2-default-text");
            setDefaultBtn.classList.add("is-default");
            if (txt) {
                txt.textContent = "Saved";
                setTimeout(refreshDefaultBtn, 1500);
            }
        });
        refreshDefaultBtn();
    }

    // Guard toggle chips reflect their checkbox state (chips wrap the inputs).
    ["guardrails-scan-checkbox", "guardrails-outbound-checkbox"].forEach((id) => {
        const cb = document.getElementById(id);
        if (!cb) return;
        const chip = cb.closest(".cp2-guard");
        const sync = () => { if (chip) chip.classList.toggle("on", cb.checked); };
        cb.addEventListener("change", sync);
        sync();
    });

    // Character count
    if (promptInput && charCount) {
        promptInput.addEventListener("input", () => {
            charCount.textContent = `${promptInput.value.length} characters`;
        });
    }

    // Enter key to submit (Ctrl+Enter for new line)
    if (promptInput) {
        promptInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.ctrlKey && !e.shiftKey) {
                e.preventDefault();
                analyzeBtn.click();
            }
        });
    }

    if (analyzeBtn) {
        analyzeBtn.addEventListener("click", async () => {
            const prompt = promptInput.value.trim();
            const useGuardrails = document.getElementById("guardrails-scan-checkbox").checked;
            const useGuardrailsOutbound = document.getElementById("guardrails-outbound-checkbox").checked;

            if (!prompt) return;

            const modelProvider = providerSelect ? providerSelect.value : 'openai';
            const modelName = modelSelect ? modelSelect.value : '';

            setLoading(true, analyzeBtn);
            // Open the progress modal immediately so the scan shows staged
            // progress (inbound → LLM → outbound) instead of a bare spinner.
            showScanning({
                useInbound: useGuardrails,
                useOutbound: useGuardrailsOutbound,
                provider: modelProvider,
                model: modelName,
            });

            try {
                const response = await fetch("/api/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        prompt,
                        use_guardrails: useGuardrails,
                        use_guardrails_outbound: useGuardrailsOutbound,
                        model_provider: modelProvider,
                        model_name: modelName
                    }),
                });
                const data = await response.json();

                if (!response.ok) throw new Error(data.error || "Analysis failed");

                data.model_provider = modelProvider;
                data.model_name = modelName;
                displayResults(data);

                if (data.openai_response && (
                    data.openai_response.includes("not configured") ||
                    data.openai_response.includes("API Key not configured")
                )) {
                    showNotification(data.openai_response, 'warning');
                }
            } catch (error) {
                const m = document.getElementById("result-modal");
                if (m) m.classList.add("hidden");
                showNotification(error.message, 'error');
            } finally {
                setLoading(false, analyzeBtn);
            }
        });
    }

    // Modal close handlers
    const resultModal = document.getElementById("result-modal");
    const closeModalBtn = document.getElementById("close-result-modal");

    if (closeModalBtn) {
        closeModalBtn.addEventListener("click", () => {
            resultModal.classList.add("hidden");
        });
    }

    // Close on outside click
    window.addEventListener("click", (e) => {
        if (e.target === resultModal) {
            resultModal.classList.add("hidden");
        }
    });

    // --- New Logic for Triggers and Batch Running ---
    const triggersList = document.getElementById("examples-list");
    const searchInput = document.getElementById("example-search");
    const runAllBtn = document.getElementById("run-all-btn");
    let allTriggers = [];

    // Load triggers on init
    loadTriggers();

    async function loadTriggers() {
        try {
            const response = await fetch("/api/triggers");
            allTriggers = await response.json();
            renderTriggers(allTriggers);
        } catch (error) {
            console.error("Failed to load triggers:", error);
            if (triggersList) {
                triggersList.innerHTML = '<div class="error-message">Failed to load triggers</div>';
            }
        }
    }

    function renderTriggers(triggers) {
        if (!triggersList) return;
        triggersList.innerHTML = "";

        if (triggers.length === 0) {
            triggersList.innerHTML = '<div class="no-results">No triggers found</div>';
            return;
        }

        // Group by category
        const categorized = {};
        triggers.forEach(trigger => {
            if (!categorized[trigger.category]) categorized[trigger.category] = [];
            categorized[trigger.category].push(trigger);
        });

        // Render categories
        Object.keys(categorized).sort().forEach(category => {
            const section = document.createElement("div");
            section.className = "example-category";
            section.innerHTML = `<h4>${category}</h4>`;

            const grid = document.createElement("div");
            grid.className = "example-grid-small";

            categorized[category].forEach(trigger => {
                const card = document.createElement("div");
                card.className = "mini-card";
                card.innerHTML = `
                    <div class="card-content">
                        <span class="card-icon">←</span>
                        ${trigger.prompt}
                    </div>
                `;
                card.title = "Click to use this trigger in the playground";

                card.addEventListener("click", () => {
                    if (promptInput) {
                        promptInput.value = trigger.prompt;
                        promptInput.dispatchEvent(new Event('input'));
                        // Focus the prompt without yanking the page to the top.
                        promptInput.focus({ preventScroll: true });
                    }
                });

                grid.appendChild(card);
            });

            section.appendChild(grid);
            triggersList.appendChild(section);
        });
    }

    // Search functionality
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            const term = e.target.value.toLowerCase();
            const filtered = allTriggers.filter(ex =>
                ex.prompt.toLowerCase().includes(term) ||
                ex.category.toLowerCase().includes(term)
            );
            renderTriggers(filtered);
        });
    }

    // Batch Runner Logic
    if (runAllBtn) {
        runAllBtn.addEventListener("click", () => {
            const batchModal = document.getElementById("batch-modal");
            if (batchModal) {
                batchModal.classList.remove("hidden");
                runBatchScan(allTriggers);
            }
        });
    }

    // Batch Modal Controls
    const batchModal = document.getElementById("batch-modal");
    const closeBatchBtn = document.getElementById("close-batch-modal");
    const cancelBatchBtn = document.getElementById("batch-cancel-btn");
    const pauseBatchBtn = document.getElementById("batch-pause-btn");

    let isBatchRunning = false;
    let isBatchPaused = false;
    let batchController = null;

    if (closeBatchBtn) {
        closeBatchBtn.addEventListener("click", () => stopBatchScan());
    }

    if (cancelBatchBtn) {
        cancelBatchBtn.addEventListener("click", () => stopBatchScan());
    }

    if (pauseBatchBtn) {
        pauseBatchBtn.addEventListener("click", () => {
            isBatchPaused = !isBatchPaused;
            pauseBatchBtn.innerHTML = isBatchPaused
                ? '<span class="icon">▶️</span> Resume'
                : '<span class="icon">⏸️</span> Pause';
        });
    }

    async function runBatchScan(examples) {
        if (isBatchRunning) return;
        isBatchRunning = true;
        isBatchPaused = false;
        batchController = new AbortController();

        const progressBar = document.getElementById("batch-progress-bar");
        const counter = document.getElementById("batch-counter");
        const statusText = document.getElementById("batch-status-text");
        const currentPrompt = document.getElementById("batch-current-prompt");
        const logList = document.getElementById("batch-log-list");

        // Reset UI
        if (logList) logList.innerHTML = "";
        if (progressBar) progressBar.style.width = "0%";
        if (counter) counter.textContent = `0/${examples.length}`;
        if (statusText) statusText.textContent = "Scanning...";
        if (pauseBatchBtn) {
            pauseBatchBtn.innerHTML = '<span class="icon">⏸️</span> Pause';
            pauseBatchBtn.disabled = false;
        }

        let completed = 0;
        const total = examples.length;

        // Get current settings for the batch run
        const useGuardrails = document.getElementById("guardrails-scan-checkbox").checked;
        const useGuardrailsOutbound = document.getElementById("guardrails-outbound-checkbox").checked;
        const modelProvider = providerSelect ? providerSelect.value : 'openai';
        const modelName = modelSelect ? modelSelect.value : '';

        for (const example of examples) {
            if (!isBatchRunning) break;

            // Handle Pause
            while (isBatchPaused) {
                if (!isBatchRunning) break;
                await new Promise(r => setTimeout(r, 100));
            }

            // Update Current Item
            if (currentPrompt) currentPrompt.textContent = example.prompt;

            try {
                const response = await fetch("/api/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        prompt: example.prompt,
                        use_guardrails: useGuardrails,
                        use_guardrails_outbound: useGuardrailsOutbound,
                        model_provider: modelProvider,
                        model_name: modelName
                    }),
                    signal: batchController.signal
                });

                const result = await response.json();

                // Add to log
                if (logList) {
                    const logItem = document.createElement("div");
                    logItem.className = "batch-log-item clickable";

                    const isFlagged = result.flagged || (result.attack_vectors && result.attack_vectors.length > 0);
                    const statusIcon = isFlagged ? "⚠️" : "✅";
                    const statusClass = isFlagged ? "status-danger" : "status-safe";

                    logItem.innerHTML = `
                        <span class="batch-log-icon">${statusIcon}</span>
                        <div class="batch-log-content">
                            <div class="batch-log-prompt">${example.prompt}</div>
                            <div class="batch-log-result ${statusClass}">
                                ${isFlagged ? "Threat Detected" : "Safe"}
                            </div>
                        </div>
                        <span class="batch-log-view">View →</span>
                    `;

                    // Store the result data for click handler
                    const resultData = {
                        ...result,
                        prompt: example.prompt,
                        model_provider: modelProvider,
                        model_name: modelName
                    };

                    logItem.addEventListener("click", () => {
                        // Show result modal on top (don't hide batch modal)
                        displayResults(resultData);
                    });

                    logList.insertBefore(logItem, logList.firstChild);
                }

            } catch (err) {
                if (err.name === 'AbortError') break;
                console.error("Batch scan error:", err);
            }

            completed++;
            if (counter) counter.textContent = `${completed}/${total}`;
            if (progressBar) progressBar.style.width = `${(completed / total) * 100}%`;

            // Add delay to prevent rate limiting (OpenAI Tier 0 is very strict)
            if (completed < total && isBatchRunning) {
                await new Promise(r => setTimeout(r, 2000));
            }
        }

        isBatchRunning = false;
        if (statusText) statusText.textContent = "Scan Complete";
        if (pauseBatchBtn) pauseBatchBtn.disabled = true;
    }

    function stopBatchScan() {
        isBatchRunning = false;
        if (batchController) batchController.abort();
        if (batchModal) batchModal.classList.add("hidden");
    }
}

// Export for potential standalone use
export { setLoading, displayResults };
