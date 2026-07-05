# AI Guardrails Demo

![AI Guardrails Demo](https://img.shields.io/badge/Security-AI Guardrails%20Demo-blueviolet?style=for-the-badge)
![Python](https://img.shields.io/badge/Backend-Flask-green?style=for-the-badge)
![JavaScript](https://img.shields.io/badge/Frontend-ES6%20Modules-yellow?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)

A demonstration platform for **AI Guardrails**, showcasing AI/LLM security capabilities through real-time prompt analysis, threat detection, and interactive visualization tools.

---

## Overview

This is a full-featured web application designed to demonstrate the power of the AI Guardrails security platform. It provides security professionals and AI developers with a hands-on environment to test, analyze, and understand LLM security vulnerabilities through an intuitive interface. Access is protected by a login screen (Flask-Login); an initial admin user is seeded from environment variables on first run.

### Key Capabilities

**Security Playground**

- Split-screen interface enabling efficient prompt testing and analysis
- Support for multiple LLM providers: OpenAI, Azure OpenAI, and Google Gemini
- Real-time traffic flow visualization showing request/response pipelines
- Comprehensive trigger library with 50+ documented attack vectors
- Batch scanning capabilities for automated security testing

**Analytics Dashboard**

- Real-time metrics tracking total scans, threats blocked, and success rates
- Interactive visualization charts for threat distribution and scan activity
- Time-based filtering (1 hour, 24 hours, 7 days)
- Professional PDF report generation for compliance and documentation

**Log Management**

- Complete audit trail of all security scans with full JSON payloads
- Advanced filtering by date range, attack vector, and detection status
- Export functionality supporting both JSON and CSV formats
- Pagination support for handling large datasets efficiently

**Market Analysis & Benchmarking**

- Side-by-side comparison with **Azure AI Content Safety** (Cloud baseline)
- Performance benchmarking against **LLM Guard** (Open-source toolkit)
- Comparative visualization charts showing threat confidence across vendors
- Unified configuration for multi-vendor security evaluation

---

## Architecture

### Technology Stack

**Backend Infrastructure**

- **Flask**: Lightweight Python web framework for API and routing
- **SQLAlchemy**: Database ORM for SQLite-based persistent storage
- **SQLite**: Embedded database for logs and application settings
- **Flasgger**: Automated API documentation generation

**Frontend Technologies**

- **Vanilla JavaScript**: ES6 modules for modular, maintainable code
- **CSS3**: Modern styling with glassmorphism effects and dark mode support
- **Chart.js**: Interactive data visualizations for analytics
- **No Framework Dependencies**: Pure web technologies for maximum flexibility

**AI Integration**

- **AI Guardrails**: Primary security scanning engine (inbound + outbound)
- **OpenAI**: GPT model integration for response generation
- **Azure OpenAI**: Enterprise OpenAI deployment support
- **Google Gemini**: Google's generative AI model support
- **Ollama**: Local LLM support for privacy-focused testing

**Benchmarking Engines**

- **Azure AI Content Safety**: cloud baseline comparison (`azure-ai-contentsafety`)
- **LLM Guard**: open-source toolkit comparison, run locally (`llm-guard`; models lazy-load on first use)

### Security Features

- Login-protected UI (Flask-Login) — all pages require authentication
- Inbound prompt scanning to detect injection attacks before LLM processing
- Outbound response scanning to identify data leakage or harmful content
- Multi-detector threat identification (PII, prompt injection, jailbreak attempts)
- Real-time threat categorization and attack vector classification
- Persistent logging (SQLite) for security auditing and compliance requirements
- Per-IP rate limiting (Flask-Limiter, in-memory or Redis-backed)

---

## Getting Started

### Prerequisites

Before installation, ensure you have the following:

- **Python 3.11 or higher**: Required for application runtime
- **AI Guardrails API Key**: Obtain from the [AI Guardrails platform](https://platform.lakera.ai/)
- **Optional LLM API Keys**: For OpenAI, Azure OpenAI, or Google Gemini integration
- **Ollama** (optional): For local LLM testing (requires running instance)
- **Docker** (optional): For containerized deployment

### CI/CD Pipeline

This project uses GitHub Actions (`.github/workflows/ci.yml`).

- **Test**: Runs pytest (with coverage) and flake8 linting on Python 3.11.
- **Security**: Scans for vulnerabilities using Trivy.
- **Build & Push**: On pushes to `main`, builds the Docker image and pushes it to GitHub Container Registry (GHCR).
- **Deploy**: A placeholder job — enabling real deployment requires configuring SSH secrets or a self-hosted runner (see the comments in the workflow).

#### Standard Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/alshawwaf/AI Guardrails-Demo.git
   cd AI Guardrails-Demo
   ```

2. **Create Virtual Environment**

   ```bash
   python -m venv venv
   
   # Windows
   .\venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**

   Copy the example environment file and configure your API keys:

   ```bash
   cp .env.example .env
   ```

   Edit `.env` with your credentials:

   ```env
   LAKERA_API_KEY=your_guardrails_api_key
   LAKERA_PROJECT_ID=your_project_id
   
   # Optional: Configure LLM providers
   OPENAI_API_KEY=your_openai_key
   AZURE_OPENAI_API_KEY=your_azure_key
   GEMINI_API_KEY=your_gemini_key
   
   # Initial admin login (seeded on first run)
   DEFAULT_ADMIN_EMAIL=admin@example.com
   DEFAULT_ADMIN_PASSWORD=change_me_please
   FLASK_SECRET_KEY=change_this_to_a_random_secret_string
   
   # Application settings
   APP_PORT=9000
   ```

   The full set of options is documented in `.env.example` and the [Configuration Reference](docs/CONFIGURATION.md).

5. **Initialize and Run**

   ```bash
   python app.py
   ```

   Access the application at `http://127.0.0.1:9000`

#### Docker Deployment

For containerized deployment:

1. **Build the Docker Image**

   ```bash
   docker build -t ai-guardrails-demo .
   ```

2. **Run the Container**

   ```bash
   docker run -p 9000:9000 --env-file .env ai-guardrails-demo
   ```

### Full Environment (with Redis)

For a complete setup with Redis-backed rate limiting and a Redis web UI, use the top-level `docker-compose.yml`:

```bash
# Start the core services (web + Redis + Redis Commander)
docker compose up -d

# Add the production profile (Nginx reverse proxy + automated backups)
docker compose --profile production up -d

# View services
docker compose ps
```

**Services included:**

- Main application (`web`)
- Redis for distributed rate limiting (host port `6380` → container `6379`)
- Redis Commander (web UI at <http://localhost:8082>)
- Nginx reverse proxy (`production` profile)
- Automated daily backup service (`production` profile)

> A `Makefile` wraps these commands (`make dev`, `make prod`, `make logs`, `make health`, `make backup`, `make test`, …); run `make help` for the full list.

See the [Full Environment Guide](docs/PRODUCTION_GUIDE.md) for a service-by-service breakdown, and [PRODUCTION.md](docs/PRODUCTION.md) for the single-container / Gunicorn path and production checklist.

The application will be accessible at `http://localhost:9000`

---

## Configuration

### Environment Variables

The application supports the following configuration options via `.env`:

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `LAKERA_API_KEY` | AI Guardrails API authentication key | Yes | - |
| `LAKERA_PROJECT_ID` | AI Guardrails project identifier | Yes | - |
| `LAKERA_API_URL` | AI Guardrails API endpoint | No | `https://api.lakera.ai/v2/guard` |
| `OPENAI_API_KEY` | OpenAI API key | No | - |
| `OPENAI_API_URL` | OpenAI API endpoint | No | `https://api.openai.com/v1/chat/completions` |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | No | - |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | No | - |
| `AZURE_OPENAI_DEPLOYMENT` | Azure deployment name | No | `gpt-4o-mini-2024-07-18` |
| `AZURE_CONTENT_SAFETY_KEY` | Azure AI Content Safety key (benchmarking) | No | - |
| `AZURE_CONTENT_SAFETY_ENDPOINT` | Azure AI Content Safety endpoint (benchmarking) | No | - |
| `GEMINI_API_KEY` | Google Gemini API key | No | - |
| `OLLAMA_API_URL` | Ollama API URL | No | `http://localhost:11434` |
| `OLLAMA_TIMEOUT` | Ollama request timeout (seconds) | No | `120` |
| `APP_PORT` | Application port | No | `9000` |
| `LOGS_DIR` | Log file directory | No | `logs` |
| `LOG_FILENAME` | Log file name | No | `application.log` |
| `CORS_ORIGINS` | Allowed origins for `/api/*` (comma-separated, or `*`) | No | `*` |
| `RATE_LIMIT_DAILY` | Requests per day per IP | No | `200` |
| `RATE_LIMIT_HOURLY` | Requests per hour per IP | No | `50` |
| `RATE_LIMIT_STORAGE` | Rate-limit backend (`memory://` or `redis://…`) | No | `memory://` |
| `DEFAULT_ADMIN_EMAIL` | Initial admin login, seeded on first run | No | `admin@example.com` |
| `DEFAULT_ADMIN_PASSWORD` | Initial admin password, seeded on first run | No | `change_me_please` |
| `FLASK_SECRET_KEY` | Flask session secret (set a random value in production) | No | - |

Additional Gunicorn tuning variables (`GUNICORN_WORKERS`, `GUNICORN_TIMEOUT`, `GUNICORN_BIND`) are documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### Runtime Configuration

Additional settings can be configured through the Settings page in the web interface:

- API key management
- Default LLM provider selection
- Model preferences

---

## Usage

### Basic Workflow

1. **Navigate to Playground**: Access the main testing interface
2. **Enter Prompt**: Input text you want to scan for threats
3. **Configure Options**:
   - Enable AI Guardrails Inbound scan for prompt analysis
   - Enable AI Guardrails Outbound scan for response checking
   - Select LLM provider and model
4. **Execute Scan**: Click "Scan Input" to process
5. **Review Results**: Examine the traffic flow visualization and threat detection results

### Batch Testing

1. Access the Trigger Library on the right panel
2. Click "Run All Triggers" to execute automated security testing
3. Monitor progress in the batch scan modal
4. Review detected threats in the scan log

### Analytics and Reporting

1. Navigate to the Dashboard
2. Select time range (1 hour, 24 hours, or 7 days)
3. Review threat distribution and scan activity charts
4. Export PDF reports for documentation

---

## API Documentation

Interactive API documentation is available at `/apidocs/` when the application is running. The documentation includes:

- Complete endpoint specifications
- Request/response schemas
- Example payloads
- Authentication requirements

### Key Endpoints

- `GET /health` - Liveness/health check (rate-limit exempt)
- `POST /api/analyze` - Run a prompt through the inbound → LLM → outbound pipeline
- `GET /api/logs` - Retrieve paginated security logs
- `DELETE /api/logs` - Clear all logs (`DELETE /api/logs/<id>` removes one)
- `GET /api/logs/export/csv` / `GET /api/logs/export/json` - Export logs
- `GET /api/analytics` - Dashboard analytics data
- `GET /api/triggers` - List available attack triggers
- `POST /api/scan/guardrails` / `POST /api/scan/azure` / `POST /api/scan/llmguard` - Single-engine scans
- `POST /api/compare` - Compare a prompt across AI Guardrails / Azure / LLM Guard
- `GET /api/benchmark/history` / `GET /api/benchmark/stats` - Benchmarking data
- `GET /api/models/status` / `POST /api/models/toggle` / `POST /api/models/download` - Local model management

---

## Project Structure

```
AI Guardrails-Demo/
├── app.py                  # Main Flask application (routes, DB models, scan logic)
├── Dockerfile              # Container configuration (Python 3.11-slim, CPU-only torch)
├── docker-compose.yml      # Full environment (web + Redis + Redis Commander; production profile adds Nginx + backup)
├── docker-compose-dev.yml  # Lightweight dev compose (Gunicorn --reload)
├── Makefile                # Task automation (make help for targets)
├── requirements.txt        # Python dependencies
├── .env.example            # Environment template
├── data/
│   └── triggers.json       # Attack trigger library
├── demo_guides/            # Walkthrough guides for demoing each page
├── docs/                   # ARCHITECTURE / CONFIGURATION / PRODUCTION / DEVELOPER_GUIDE
├── nginx/
│   └── nginx.conf          # Reverse-proxy config (production profile)
├── scripts/
│   ├── start_production.sh # Container entrypoint
│   ├── backup_db.py        # SQLite backup (keeps 10 most recent)
│   └── warmup_models.py    # Optional model warmup
├── static/
│   ├── css/                # Modular stylesheets (base / components / pages)
│   └── js/                 # ES6 JavaScript modules (shared / pages / main.js)
├── templates/              # Jinja2 HTML templates
└── tests/                  # pytest suite
```

> `instance/` (SQLite DB), `logs/`, `backups/`, and `models_cache/` are created at runtime and are git-ignored.

---

## Development

### Setting Up Development Environment

Refer to the [Developer Guide](docs/DEVELOPER_GUIDE.md) for comprehensive setup instructions, coding standards, and contribution guidelines.

### Running Tests

The `tests/` suite runs under pytest (also executed in CI):

```bash
python -m pytest tests/
# or
make test
```

### Code Style

- **Python**: Follow PEP 8 guidelines
- **JavaScript**: Use ES6+ features, 4-space indentation
- **CSS**: Modular architecture, split across `static/css/base`, `components`, and `pages`

### Editing Jinja Templates

The HTML files under `templates/` are Jinja2 templates. If your editor auto-formats HTML, disable it for these files — inserting spaces inside `{{ }}` expressions will break the template syntax. In VS Code, the [Jinja HTML](https://marketplace.visualstudio.com/items?itemName=samuelcolvin.jinjahtml) extension provides correct syntax highlighting.

---

## Documentation

Additional resources for developers and users:

- **[Developer Guide](docs/DEVELOPER_GUIDE.md)**: Comprehensive development documentation
- **[Architecture Overview](docs/ARCHITECTURE.md)**: System design and technical details
- **[Production Deployment](docs/PRODUCTION.md)**: Production deployment guide
- **[Configuration Reference](docs/CONFIGURATION.md)**: Complete environment variable reference
- **[Demo Documentation](https://platform.lakera.ai/docs)**: Official API reference

---

## License

This project is licensed under the MIT License. See LICENSE file for details.

---

## Support

For issues, questions, or contributions:

- Open an issue on GitHub
- Consult the documentation
- Contact AI Guardrails support for API-related questions
