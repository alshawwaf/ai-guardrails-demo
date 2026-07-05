# Guide 3: Logs & Auditing

The Logs page provides a granular audit trail of every interaction with the system. This is essential for forensic analysis, debugging, and compliance.

## 1. Navigating the Logs

The main table displays a chronological list of scans. Each row contains:

*   **Timestamp**: When the scan occurred.
*   **Prompt**: A snippet of the user input.
*   **Status**: Whether the request was **Allowed** (Green) or **Blocked** (Red).
*   **Attack Type**: The specific threat category detected (e.g., "jailbreak"), or "Clean" if no threat was found.
*   **Latency**: The time taken to process the request.

## 2. Filtering

You can filter the logs to find specific events:

*   **Status Filter**: Show only "Blocked" requests to investigate attacks, or "Allowed" requests to audit normal traffic.
*   **Search**: Use the search bar to find specific keywords in prompts or attack types.

## 3. Detailed Analysis

Clicking on any row in the log table opens a detailed view (JSON payload). This contains the raw data returned by AI Guardrails Demo, including:

*   **Full Prompt**: The complete text of the user input.
*   **Model Used**: The LLM model that was targeted.
*   **AI Guardrails Response**: The detailed security analysis, including scores for various detectors.

## 4. Exporting Data

For external analysis or archiving, you can export the logs:

*   **Export to CSV**: Best for spreadsheet analysis (Excel, Google Sheets).
*   **Export to JSON**: Best for programmatic analysis or importing into other tools.

Buttons for these actions are located at the top right of the Logs page.
