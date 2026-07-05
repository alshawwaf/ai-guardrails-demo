# Azure AI Content Safety Setup Guide

This guide describes how to configure Azure AI Content Safety to work with the AI Guardrails Demo application.

## 1. Create the Azure Resource

1. Log in to the [Azure Portal](https://portal.azure.com).
2. Search for **Azure AI Services** or **Content Safety**.
3. Click **Create** under **Content Safety**.
4. Configure the resource:
    * **Subscription**: Select your active Azure subscription.
    * **Resource Group**: Select an existing one or create a new one.
    * **Region**: Choose a region close to you (e.g., East US).
    * **Name**: Give your resource a unique name (e.g., `ai-guardrails-demo-safety`).
    * **Pricing Tier**: Choose **F0 (Free)** if available, or **S0**.
5. Click **Review + create**, then **Create**.
6. Once deployed, navigate to the resource.

## 2. Obtain Credentials

1. Select **Keys and Endpoint** in the left-hand menu under **Resource Management**.
2. Copy your **KEY 1** (or KEY 2).
    > [!IMPORTANT]
    > Azure security keys are exactly **32 characters long** and consist only of letters (a-f) and numbers (0-9). If your key is longer or contains other characters, you may have copied a Connection String or Project ID by mistake.
3. Copy the **Endpoint** (it should look like `https://<your-resource-name>.cognitiveservices.azure.com/`).

## 3. Configure the Application

### Option A: Via `.env` file (Recommended)

1. Open your `.env` file in the project root.
2. Add or update the following lines:

    ```bash
    AZURE_CONTENT_SAFETY_KEY=your_copied_key_here
    AZURE_CONTENT_SAFETY_ENDPOINT=your_copied_endpoint_here
    ```

### Option B: Via the UI Settings

1. Start the application (`docker compose up -d`).
2. Navigate to the **Configuration > Settings** page in the menu.
3. Enter the **Azure Content Safety Key** and **Azure Content Safety Endpoint**.
4. Click **Update Settings**.

## 4. Verify the Integration

1. Navigate to the **Monitor > Benchmarking** page (or use the **Playground**).
2. Ensure you are using a feature that triggers multi-vendor scans (like the **Compare** view in older versions or specific benchmarking triggers).
3. Check the logs or the real-time results for a row labeled **Azure AI**. If configured correctly, it will show a score and severity breakdown.

> [!TIP]
> Azure Content Safety classifies content into four categories: Hate, Self-Harm, Sexual, and Violence. The app normalizes these 0-7 severity levels into a 0-100 score for easy comparison with AI Guardrails.
