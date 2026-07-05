# Guide 2: Dashboard & Analytics

The Dashboard provides a high-level view of your application's security posture. It visualizes data from all scans to help you understand threat trends and system usage.

## 1. Key Metrics

At the top of the dashboard, you will see three key metric cards:

*   **Total Scans**: The aggregate number of prompts processed by the system.
*   **Threats Blocked**: The number of prompts or responses that triggered a AI Guardrails Demo protection.
*   **Block Rate**: The percentage of traffic that was identified as malicious (Threats Blocked / Total Scans).

## 2. Visualizations

*   **Threat Distribution**: A doughnut chart showing the breakdown of different attack types (e.g., Prompt Injection, PII, Jailbreak). This helps identify the most common threats targeting your system.
*   **Scan Activity**: A bar chart showing the volume of scans over time. This is useful for identifying traffic spikes or usage patterns.

## 3. Time Filtering

You can filter the data displayed on the dashboard using the time range selector in the top right corner:

*   **1 Hour**: Real-time monitoring of immediate activity.
*   **24 Hours**: Daily overview.
*   **7 Days**: Weekly trend analysis.

## 4. Reporting

For compliance and stakeholder reporting, you can generate a PDF report of the current dashboard view.

1.  **Configure View**: Select the desired time range.
2.  **Export**: Click the **Export Report** button (if available) or use your browser's print function (Ctrl+P / Cmd+P) and select "Save as PDF". The dashboard is optimized for printing.
