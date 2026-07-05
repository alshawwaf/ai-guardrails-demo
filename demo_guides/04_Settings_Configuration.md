# Guide 4: Settings & Configuration

The Settings page allows you to configure the application's connections to external services and customize its behavior.

## 1. AI Guardrails Configuration

This is the most critical section. You must provide valid credentials to use AI Guardrails Demo.

*   **AI Guardrails API Key**: Your secret key from the AI Guardrails Platform.
*   **Project ID**: The specific project identifier associated with your key.

## 2. LLM Providers

You can configure multiple LLM providers to test how different models respond to attacks.

### OpenAI
*   **API Key**: Your OpenAI API key.

### Azure OpenAI
*   **API Key**: Your Azure OpenAI API key.
*   **Endpoint**: The full URL of your Azure resource (e.g., `https://my-resource.openai.azure.com/`).
*   **Deployment Name**: The name of the model deployment you created in Azure AI Studio.

### Google Gemini
*   **API Key**: Your Google Cloud API key with access to the Gemini API.

### Ollama (Local LLM)
*   **API URL**: The address of your local Ollama instance (default: `http://localhost:11434`).
*   **Timeout**: The maximum time (in seconds) to wait for a response. Increase this if you are using large models on slower hardware (default: `120`).

## 3. Saving Changes

After entering or updating any information, click the **Save Changes** button at the bottom of the page. A success message will appear to confirm that your settings have been applied.
