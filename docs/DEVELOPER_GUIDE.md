# Developer Guide

Welcome to the Lakera Guard Demo developer documentation. This guide is designed to help you understand the project structure, set up your development environment, and contribute effectively.

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js (optional, for future frontend tooling)
- Git

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/alshawwaf/Lakera-Demo.git
    cd Lakera-Demo
    ```

2.  **Set up Virtual Environment**
    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    # Mac/Linux
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: If `requirements.txt` is missing, install core packages:*
    ```bash
    pip install flask Flask-Login python-dotenv requests Flask-SQLAlchemy google-genai
    ```

4.  **Configuration**
    Create a `.env` file in the root directory:
    ```env
    # Lakera Guard
    LAKERA_API_KEY=your_key
    LAKERA_PROJECT_ID=your_id

    # Optional LLMs
    OPENAI_API_KEY=your_key
    AZURE_OPENAI_API_KEY=your_key
    GEMINI_API_KEY=your_key
    APP_PORT=9000
    ```

5.  **Run the Application**
    ```bash
    python app.py
    ```
    Visit `http://127.0.0.1:9000`

### Docker Deployment

To run the application using Docker:

1.  **Build the Docker Image**
    ```bash
    docker build -t lakera-demo .
    ```

2.  **Run the Container**
    Make sure your `.env` file is configured.
    ```bash
    docker run -p 9000:9000 --env-file .env lakera-demo
    ```

## Architecture

The application follows a **modular hybrid architecture**, combining a Flask backend with a vanilla JavaScript frontend that uses ES6 modules.

### Backend (`app.py`)
- **Framework**: Flask
- **Database**: SQLite (via SQLAlchemy)
- **Auth**: Flask-Login; all UI pages are `@login_required`. An initial admin is seeded from `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD`.
- **API Routes**:
    - `/api/analyze`: Core logic for Lakera Guard scans.
    - `/api/analytics`: Dashboard metrics.
    - `/api/logs`: Log management.
    - `/api/compare`, `/api/scan/*`, `/api/benchmark/*`: Multi-vendor benchmarking (Lakera / Azure AI Content Safety / LLM Guard).

### Frontend (`static/js/`)
- **Entry Point**: `main.js` handles routing and dynamic imports.
- **Pages**:
    - `pages/playground.js`: Interactive testing interface.
    - `pages/dashboard.js`: Chart.js visualizations.
    - `pages/logs.js`: Data tables and filtering.
- **Shared**: `shared/utils.js` and `shared/traffic-flow.js`.

### Data Flow
1.  **User Input** → `playground.js`
2.  **API Call** → `POST /api/analyze`
3.  **Backend** → Lakera Guard Inbound → LLM (OpenAI/Azure/Gemini/Ollama) → Lakera Guard Outbound
4.  **Response** → Frontend Visualization (Traffic Flow)

## Project Structure

```
lakera-demo/
├── .github/               # CI/CD workflows
├── app.py                 # Main application entry point
├── data/                  # Static data files
│   └── triggers.json      # Trigger library
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md    # Detailed architectural deep-dive
│   ├── CONFIGURATION.md   # Environment variable reference
│   ├── PRODUCTION.md      # Production deployment guide
│   └── DEVELOPER_GUIDE.md # This file
├── instance/              # SQLite database
├── logs/                  # Application logs
├── static/                # Frontend assets
│   ├── css/               # Stylesheets (Modular)
│   └── js/                # ES6 JavaScript Modules
├── templates/             # HTML Templates (Jinja2)
├── docker-compose.yml     # Docker composition
├── Makefile               # Task automation
└── requirements.txt       # Python dependencies
```

## Development Standards

- **Code Style**: Follow PEP 8 for Python. Use consistent indentation (4 spaces) for JavaScript.
- **Commits**: Use descriptive commit messages.
- **Testing**: Run tests before pushing changes using `make test`.
- **CI/CD**: Test workflows locally using `act`.

## Testing CI/CD Locally

You can test the GitHub Actions pipeline locally using [nektos/act](https://github.com/nektos/act).

1.  **List available jobs**:
    ```bash
    act -l
    ```

2.  **Run the test job**:
    ```bash
    act -j test
    ```

3.  **Run the full pipeline** (requires Docker):
    ```bash
    act
    ```
    *Note: Some steps like pushing to GHCR will fail locally without valid credentials/secrets.*

## GitHub Authentication

To interact with the repository (push code, trigger workflows), you need to authenticate with GitHub.

### Option 1: GitHub CLI (Recommended)

If you use **Passkeys** or **2FA**, the easiest method is using the GitHub CLI with a Personal Access Token (PAT).

1.  **Generate a Token**:
    - Go to [GitHub Settings > Developer settings > Personal access tokens > Tokens (classic)](https://github.com/settings/tokens).
    - Generate a new token with `repo`, `read:org`, and `workflow` scopes.
    - Copy the token.

2.  **Login via CLI**:
    ```bash
    gh auth login
    ```
    - Select **GitHub.com** -> **HTTPS** -> **Paste an authentication token**.
    - Paste your token when prompted.

### Option 2: SSH Key

If you prefer SSH:
1.  Generate a key: `ssh-keygen -t ed25519 -C "your@email.com"`
2.  Add the public key (`cat ~/.ssh/id_ed25519.pub`) to [GitHub SSH Keys](https://github.com/settings/keys).
3.  Test connection: `ssh -T git@github.com`

### Troubleshooting Authentication

If you encounter `Authentication failed` or `osxkeychain` errors on Linux:

1.  **Check Credential Helper**:
    ```bash
    git config --global credential.helper
    ```
    If it says `osxkeychain`, unset it:
    ```bash
    git config --global --unset credential.helper
    ```

2.  **Configure GitHub CLI Helper**:
    If you are logged in with `gh`, tell git to use it:
    ```bash
    gh auth setup-git
    ```

## Contributing

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

## Resources

- [Lakera Guard API Documentation](https://platform.lakera.ai/docs)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Chart.js Documentation](https://www.chartjs.org/)
