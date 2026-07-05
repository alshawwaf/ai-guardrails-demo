// ============================================
// Logs Page Module
// ============================================

/**
 * Initialize logs page
 */
export function initLogs() {
    const filterBtn = document.getElementById("filter-btn");
    const clearAllBtn = document.getElementById("clear-all-btn");
    const startDateInput = document.getElementById("start-date");
    const endDateInput = document.getElementById("end-date");

    // Modal elements
    const modal = document.getElementById("log-modal");
    const closeModal = document.querySelector(".close-modal");
    const modalRequest = document.getElementById("modal-request");
    const modalResponse = document.getElementById("modal-response");

    // Confirmation Modal elements
    const confirmModal = document.getElementById("confirmation-modal");
    const closeConfirmModal = document.getElementById("close-confirm-modal");
    const confirmCancelBtn = document.getElementById("confirm-cancel-btn");
    const confirmOkBtn = document.getElementById("confirm-ok-btn");
    const confirmMessage = document.getElementById("confirmation-message");
    let logIdToDelete = null;
    let isDeleteAll = false;

    // Export Buttons
    const exportJsonBtn = document.getElementById("export-json-btn");
    const exportCsvBtn = document.getElementById("export-csv-btn");

    // Pagination elements
    const firstPageBtn = document.getElementById("first-page-btn");
    const prevPageBtn = document.getElementById("prev-page-btn");
    const nextPageBtn = document.getElementById("next-page-btn");
    const lastPageBtn = document.getElementById("last-page-btn");
    const pageIndicator = document.getElementById("page-indicator");
    const paginationInfoText = document.getElementById("pagination-info-text");
    const perPageSelect = document.getElementById("per-page-select");

    // Pagination state
    let currentPage = 1;
    let perPage = 20;
    let totalPages = 1;
    let totalLogs = 0;

    function triggerDownload(url, filename) {
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    if (exportJsonBtn) {
      exportJsonBtn.addEventListener("click", () => {
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
        triggerDownload("/api/logs/export/json", `guardrails_logs_${timestamp}.json`);
      });
    }

    if (exportCsvBtn) {
      exportCsvBtn.addEventListener("click", () => {
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
        triggerDownload("/api/logs/export/csv", `guardrails_logs_${timestamp}.csv`);
      });
    }

    // Pagination event listeners
    if (firstPageBtn) {
      firstPageBtn.addEventListener("click", () => {
        currentPage = 1;
        loadLogs();
      });
    }

    if (prevPageBtn) {
      prevPageBtn.addEventListener("click", () => {
        if (currentPage > 1) {
          currentPage--;
          loadLogs();
        }
      });
    }

    if (nextPageBtn) {
      nextPageBtn.addEventListener("click", () => {
        if (currentPage < totalPages) {
          currentPage++;
          loadLogs();
        }
      });
    }

    if (lastPageBtn) {
      lastPageBtn.addEventListener("click", () => {
        currentPage = totalPages;
        loadLogs();
      });
    }

    if (perPageSelect) {
      perPageSelect.addEventListener("change", () => {
        perPage = parseInt(perPageSelect.value);
        currentPage = 1; // Reset to first page when changing per-page
        loadLogs();
      });
    }

    if (filterBtn) filterBtn.addEventListener("click", () => {
      currentPage = 1; // Reset to first page when filtering
      loadLogs();
    });

    if (clearAllBtn) {
        clearAllBtn.addEventListener("click", () => {
            isDeleteAll = true;
            if (confirmMessage) confirmMessage.textContent = "Are you sure you want to clear all logs? This action cannot be undone.";
            if (confirmModal) confirmModal.classList.remove("hidden");
        });
    }

    // Close modal logic
    if (closeModal) closeModal.addEventListener("click", () => modal.classList.add("hidden"));
    
    // Close confirmation modal logic
    const hideConfirmModal = () => {
        confirmModal.classList.add("hidden");
        logIdToDelete = null;
        isDeleteAll = false;
    };

    if (closeConfirmModal) closeConfirmModal.addEventListener("click", hideConfirmModal);
    if (confirmCancelBtn) confirmCancelBtn.addEventListener("click", hideConfirmModal);
    
    if (confirmOkBtn) {
        confirmOkBtn.addEventListener("click", async () => {
            if (isDeleteAll) {
                await fetch("/api/logs", { method: "DELETE" });
                hideConfirmModal();
                currentPage = 1;
                loadLogs();
            } else if (logIdToDelete) {
                await fetch(`/api/logs/${logIdToDelete}`, { method: "DELETE" });
                hideConfirmModal();
                loadLogs();
            }
        });
    }

    window.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.add("hidden");
      if (e.target === confirmModal) hideConfirmModal();
    });

    // Check for URL filter parameter
    const urlParams = new URLSearchParams(window.location.search);
    const filterParam = urlParams.get("filter");

    // Initial load
    loadLogs();
    // Auto-refresh every 30s if no filter
    setInterval(() => {
      if (startDateInput && endDateInput && !startDateInput.value && !endDateInput.value) loadLogs();
    }, 30000);

    async function loadLogs() {
      try {
        let url = "/api/logs";
        const params = new URLSearchParams();
        params.append("page", currentPage);
        params.append("per_page", perPage);
        if (startDateInput && startDateInput.value)
          params.append("start_date", startDateInput.value);
        if (endDateInput && endDateInput.value) params.append("end_date", endDateInput.value);
        url += `?${params.toString()}`;

        const response = await fetch(url);
        const data = await response.json();

        let logs = data.logs || [];
        const pagination = data.pagination || {};

        // Update pagination state
        totalPages = pagination.total_pages || 1;
        totalLogs = pagination.total_logs || 0;

        // Apply attack vector filter if present (client-side)
        if (filterParam) {
          logs = logs.filter(
            (log) =>
              log.attack_vectors && log.attack_vectors.includes(filterParam)
          );
        }

        // Update pagination UI
        updatePaginationUI(pagination);

        window.currentLogs = logs; // Store for modal access
        updateLogsTable(logs);
      } catch (error) {
        console.error("Failed to load logs:", error);
      }
    }

    function updatePaginationUI(pagination) {
      // Update page indicator
      if (pageIndicator) {
        pageIndicator.textContent = `Page ${pagination.current_page} of ${pagination.total_pages}`;
      }

      // Update info text
      if (paginationInfoText) {
        const start = pagination.total_logs > 0 ? ((pagination.current_page - 1) * pagination.per_page) + 1 : 0;
        const end = Math.min(pagination.current_page * pagination.per_page, pagination.total_logs);
        paginationInfoText.textContent = `Showing ${start}-${end} of ${pagination.total_logs} logs`;
      }

      // Enable/disable buttons
      if (firstPageBtn) firstPageBtn.disabled = !pagination.has_prev;
      if (prevPageBtn) prevPageBtn.disabled = !pagination.has_prev;
      if (nextPageBtn) nextPageBtn.disabled = !pagination.has_next;
      if (lastPageBtn) lastPageBtn.disabled = !pagination.has_next;
    }

    function updateLogsTable(logs) {
      const tbody = document.querySelector("#logs-table tbody");
      if (!tbody) return;
      tbody.innerHTML = "";

      logs.forEach((log, index) => {
        const row = document.createElement("tr");
        row.onclick = () => window.openLogDetails(index);

        let statusHtml = '<span class="status-safe">Safe</span>';
        let isFlagged = false;

        if (log.error) {
          statusHtml = '<span class="status-flagged">Error</span>';
        } else if (log.result) {
          if (
            log.result.flagged ||
            (log.result.results && log.result.results.some((r) => r.flagged))
          ) {
            statusHtml = '<span class="status-flagged">Flagged</span>';
            isFlagged = true;
          }
        }

        const promptText =
          log.prompt.length > 50
            ? log.prompt.substring(0, 50) + "..."
            : log.prompt;

        // Display attack vectors as colored badges
        let attackTypesHtml = "-";
        const vectors = Array.isArray(log.attack_vectors) ? log.attack_vectors : [];
        if (vectors.length > 0) {
          attackTypesHtml = vectors
            .map((v) => {
              const color = window.getAttackColor(v);
              return `<span class="attack-badge" style="background: ${color}20; border-color: ${color}; color: ${color};">${v}</span>`;
            })
            .join(" ");
        }

        row.innerHTML = `
                    <td>${log.timestamp}</td>
                    <td title="${log.prompt}">${promptText}</td>
                    <td>${statusHtml}</td>
                    <td>${attackTypesHtml}</td>
                    <td>
                        <button class="delete-btn" onclick="window.deleteLog(event, '${log.id}')" title="Delete Log">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                        </button>
                    </td>
                `;
        tbody.appendChild(row);
      });
    }

    // Expose global functions for table actions
    window.openLogDetails = (index) => {
      const log = window.currentLogs[index];
      if (log) {
        const requestData = log.request || {};
        const responseData = log.response || log.result || log.error || {};
        
        modalRequest.textContent = Object.keys(requestData).length > 0 
            ? JSON.stringify(requestData, null, 2) 
            : "No request data available (Log may be from before migration)";
            
        modalResponse.textContent = JSON.stringify(responseData, null, 2);
        modal.classList.remove("hidden");
      }
    };

    window.deleteLog = (e, id) => {
      e.stopPropagation();
      logIdToDelete = id;
      isDeleteAll = false;
      if (confirmMessage) confirmMessage.textContent = "Are you sure you want to delete this log?";
      if (confirmModal) {
          confirmModal.classList.remove("hidden");
      }
    };
}
