# AI Guardrails Playground

Test LLM prompt-injection and jailbreak guardrails across providers in real time, then benchmark them against other vendors.

Part of the [Dev Hub](https://github.com/alshawwaf/dev-hub) ecosystem — deploy the whole suite with [ubuntu-dokploy-ai](https://github.com/alshawwaf/ubuntu-dokploy-ai).

![Backend](https://img.shields.io/badge/Backend-Flask-green?style=for-the-badge)
![Frontend](https://img.shields.io/badge/Frontend-ES6%20Modules-yellow?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)

---

## Overview

AI Guardrails Playground is a login-protected Flask web app for exploring AI/LLM security. You send a prompt through a guardrail pipeline (inbound scan → target LLM → outbound scan), watch the request/response flow in real time, and see exactly what a guardrail catches — prompt injection, jailbreaks, PII leakage, toxic content. A trigger library lets you fire known attack prompts in one click, a dashboard tracks scan metrics over time, and a benchmarking page compares the same prompt across multiple detection vendors side by side.

The guardrail engine is [Lakera Guard](https://platform.lakera.ai/) (the `LAKERA_*` variables). Target text generation can run against OpenAI, Azure OpenAI, Google Gemini, or a local Ollama model.

## Features

- **Playground** — split-screen prompt tester with a live traffic-flow visualization; toggle inbound and outbound scans independently; pick the target LLM provider and model.
- **Trigger library** — a curated set of documented attack prompts (jailbreak, injection, PII, toxicity); run one or batch-run them all against the pipeline.
- **Dashboard** — total scans, threats blocked, and success-rate metrics with threat-distribution and activity charts; 1h / 24h / 7d filters; PDF export.
- **Logs** — full audit trail of every scan with the complete JSON payload; filter by date / attack vector / status; paginated; export to CSV or JSON.
- **Benchmarking** — compare a prompt across **AI Guardrails (Lakera)**, **Azure AI Content Safety**, and **LLM Guard** (open-source, models lazy-load on first use), with comparative confidence charts.
- **Settings** — manage API keys, the default LLM provider/model, and local LLM Guard model downloads from the browser (persisted in SQLite).
- **Auth & limits** — Flask-Login on every page (admin seeded from env on first run) and per-IP rate limiting (in-memory or Redis-backed).
- **API + docs** — JSON API under `/api/*` with an interactive Swagger UI at `/apidocs/`.

## Screenshots

_Screenshots to be added._

## Quick start

### Local (Python)

```bash
git clone https://github.com/alshawwaf/ai-guardrails-demo.git
cd ai-guardrails-demo

python -m venv venv && source venv/bin/activate   # Windows: .\venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env      # add your LAKERA_API_KEY / LAKERA_PROJECT_ID (+ optional LLM keys)
python app.py             # http://127.0.0.1:9000
```

The initial admin login is seeded from `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` on first run.

### Local (Docker)

```bash
docker build -t ai-guardrails-demo .
docker run -p 9000:9000 --env-file .env ai-guardrails-demo
```

## Deployment

In production this app deploys automatically as part of the [Dev Hub](https://github.com/alshawwaf/dev-hub) suite via the [ubuntu-dokploy-ai](https://github.com/alshawwaf/ubuntu-dokploy-ai) installer, and is served at **guardrails.&lt;your-domain&gt;** behind Traefik.

For a full self-hosted stack with Redis-backed rate limiting, use the top-level `docker-compose.yml`:

```bash
docker compose up -d                          # web + Redis + Redis Commander
docker compose --profile production up -d     # + Nginx reverse proxy + daily DB backup
```

| Service | Description | Port |
|---------|-------------|------|
| `web` | The Flask application | `9000` |
| `redis` | Distributed rate-limit store | `6380` → `6379` |
| `redis-commander` | Redis web UI | `8082` |
| `nginx` | Reverse proxy (`production` profile) | `80` / `443` |
| `backup` | Daily SQLite backup (`production` profile) | — |

A `Makefile` wraps the common flows — `make dev`, `make prod`, `make logs`, `make health`, `make backup`, `make test`; run `make help` for the full list. See [docs/PRODUCTION.md](docs/PRODUCTION.md) and [docs/PRODUCTION_GUIDE.md](docs/PRODUCTION_GUIDE.md) for the full production path.

## Configuration

Set these in `.env` (see [.env.example](.env.example) and [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete reference).

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `LAKERA_API_KEY` | AI Guardrails (Lakera Guard) API key | Yes | — |
| `LAKERA_PROJECT_ID` | AI Guardrails project identifier | Yes | — |
| `LAKERA_API_URL` | Guardrails API endpoint | No | `https://api.lakera.ai/v2/guard` |
| `OPENAI_API_KEY` | OpenAI API key | No | — |
| `OPENAI_API_URL` | OpenAI chat-completions endpoint | No | `https://api.openai.com/v1/chat/completions` |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | No | — |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | No | — |
| `AZURE_OPENAI_DEPLOYMENT` | Azure deployment name | No | `gpt-4o-mini-2024-07-18` |
| `GEMINI_API_KEY` | Google Gemini API key | No | — |
| `OLLAMA_API_URL` | Ollama base URL (local LLM) | No | `http://localhost:11434` |
| `OLLAMA_TIMEOUT` | Ollama request timeout (s) | No | `120` |
| `OLLAMA_MODEL` | Default local target model | No | see `.env.example` |
| `DEFAULT_LLM_PROVIDER` | Playground default provider | No | `ollama` |
| `DEFAULT_LLM_MODEL` | Playground default model | No | see `.env.example` |
| `AZURE_CONTENT_SAFETY_KEY` | Azure AI Content Safety key (benchmarking) | No | — |
| `AZURE_CONTENT_SAFETY_ENDPOINT` | Azure AI Content Safety endpoint (benchmarking) | No | — |
| `APP_PORT` | Application port | No | `9000` |
| `CORS_ORIGINS` | Allowed origins for `/api/*` (comma-separated or `*`) | No | `*` |
| `RATE_LIMIT_DAILY` | Requests/day per IP | No | `1000000` |
| `RATE_LIMIT_HOURLY` | Requests/hour per IP | No | `100000` |
| `RATE_LIMIT_STORAGE` | Rate-limit backend (`memory://` or `redis://…`) | No | `memory://` |
| `DEFAULT_ADMIN_EMAIL` | Initial admin login, seeded on first run | No | `admin@example.com` |
| `DEFAULT_ADMIN_PASSWORD` | Initial admin password, seeded on first run | No | `change_me_please` |
| `FLASK_SECRET_KEY` | Flask session secret (set a random value) | No | — |

> The rate-limit defaults are intentionally high: when embedded in the Dev Hub desktop (iframe) a single session generates many requests, so a low limit trips instantly and breaks the demo. Gunicorn tuning (`GUNICORN_WORKERS`, `GUNICORN_TIMEOUT`, `GUNICORN_BIND`) is documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

You can also set API keys, the default provider/model, and local model preferences at runtime from the in-app **Settings** page (persisted to SQLite).

## Tech stack

- **Backend** — Flask, Flask-SQLAlchemy (SQLite), Flask-Login, Flask-Limiter, Flask-CORS, Flasgger (Swagger), Gunicorn.
- **Frontend** — vanilla ES6 JavaScript modules, modular CSS (`base` / `components` / `pages`), Chart.js — no framework.
- **Detection & LLMs** — Lakera Guard (guardrail engine); OpenAI, Azure OpenAI, Google Gemini, Ollama (target LLMs); Azure AI Content Safety and LLM Guard (benchmarking).
- **Ops** — Docker, Redis, Nginx; CPU-only PyTorch in the image (LLM Guard models cached in a `models_cache` volume, lazy-loaded).

## Project structure

```
ai-guardrails-demo/
├── app.py                  # Flask app: routes, DB models, guard/scan pipeline
├── Dockerfile              # Python 3.11-slim, CPU-only torch
├── docker-compose.yml      # Full stack (web + Redis + Redis Commander; production profile adds Nginx + backup)
├── docker-compose-dev.yml  # Lightweight dev compose
├── Makefile                # Task automation (make help)
├── data/triggers.json      # Attack trigger library
├── demo_guides/            # Per-page demo walkthroughs
├── docs/                   # ARCHITECTURE / CONFIGURATION / PRODUCTION / DEVELOPER_GUIDE
├── nginx/nginx.conf        # Reverse-proxy config (production profile)
├── scripts/                # start_production.sh, backup_db.py, warmup_models.py
├── static/                 # ES6 JS modules + modular CSS
├── templates/              # Jinja2 templates
└── tests/                  # pytest suite
```

> `instance/` (SQLite DB), `logs/`, `backups/`, and `models_cache/` are created at runtime and git-ignored.

## API

Interactive docs live at `/apidocs/` while the app is running. Key endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness check (rate-limit exempt) |
| `POST` | `/api/analyze` | Run a prompt through inbound → LLM → outbound |
| `GET` / `DELETE` | `/api/logs` | List (paginated) / clear logs (`/api/logs/<id>` deletes one) |
| `GET` | `/api/logs/export/{json,csv}` | Export logs |
| `GET` | `/api/analytics` | Dashboard analytics |
| `GET` | `/api/triggers` | List attack triggers |
| `POST` | `/api/scan/{guardrails,azure,llmguard}` | Single-engine scans |
| `POST` | `/api/compare` | Compare a prompt across all three engines |
| `GET` | `/api/benchmark/{history,stats}` | Benchmarking data |
| `GET`/`POST` | `/api/models/{status,toggle,download}` | Local LLM Guard model management |

## Development

```bash
python -m pytest tests/     # or: make test
```

- **Python** — PEP 8.
- **JavaScript** — ES6+, 4-space indentation.
- **CSS** — modular, split across `static/css/{base,components,pages}`.
- **Templates** — files under `templates/` are Jinja2; disable HTML auto-format for them (spaces inside `{{ }}` break the syntax).

CI runs on GitHub Actions (`.github/workflows/ci.yml`): pytest + flake8, a Trivy security scan, and — on pushes to `main` — a Docker image build pushed to GHCR. See the [Developer Guide](docs/DEVELOPER_GUIDE.md) and [Architecture Overview](docs/ARCHITECTURE.md) for details.

## License

Released under the [MIT License](LICENSE).
