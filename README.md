# AI Guardrails Playground

Test LLM prompt-injection and jailbreak guardrails across providers in real time, benchmark them against other vendors, and (with Gateway Mode) show the same protection enforced by a Check Point gateway.

Part of the [Dev Hub](https://github.com/alshawwaf/dev-hub) ecosystem — deploy the whole suite with [ubuntu-dokploy-ai](https://github.com/alshawwaf/ubuntu-dokploy-ai).

![Backend](https://img.shields.io/badge/Backend-Flask-green?style=for-the-badge)
![Frontend](https://img.shields.io/badge/Frontend-ES6%20Modules-yellow?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)

---

## Overview

AI Guardrails Playground is a login-protected Flask web app for exploring AI/LLM security. You send a prompt through a guardrail pipeline (inbound scan → target LLM → outbound scan), watch the request/response flow in real time, and see exactly what a guardrail catches — prompt injection, jailbreaks, PII leakage, toxic content. A trigger library lets you fire known attack prompts in one click, a dashboard tracks scan metrics over time, and a benchmarking page compares the same prompt across multiple detection vendors side by side.

The guardrail engine is [Lakera Guard](https://platform.lakera.ai/) (the `LAKERA_*` variables). Target text generation can run against OpenAI, Azure OpenAI, Anthropic, Google Gemini, or a local Ollama model.

**Gateway Mode** adds a second way to demo: instead of the app calling the guardrail API, a Check Point Quantum gateway (R82.20) inspects the developer-API traffic to the AI providers with **AI Agent Security** and blocks attacks in the network. The `aiguard` command line tool and the **Gateway Mode** web console set this up through the Check Point Management API, run the demo, and match every block to the gateway's logs. See [Gateway Mode and the aiguard CLI](#gateway-mode-and-the-aiguard-cli).

## Features

- **Playground** — split-screen prompt tester with a live traffic-flow visualization; toggle inbound and outbound scans independently; pick the target LLM provider and model.
- **Trigger library** — a curated set of documented attack prompts (jailbreak, injection, PII, toxicity); run one or batch-run them all against the pipeline.
- **Dashboard** — total scans, threats blocked, and success-rate metrics with threat-distribution and activity charts; 1h / 24h / 7d filters; PDF export.
- **Logs** — full audit trail of every scan with the complete JSON payload; filter by date / attack vector / status; paginated; export to CSV or JSON.
- **Benchmarking** — compare a prompt across **AI Guardrails (Lakera)**, **Azure AI Content Safety**, and **LLM Guard** (open-source, models lazy-load on first use), with comparative confidence charts.
- **Settings** — manage API keys, the default LLM provider/model, and local LLM Guard model downloads from the browser. API keys are stored in SQLite encrypted with AES-256-GCM and are never sent back to the browser (only a masked hint).
- **Gateway Mode** — a step-by-step console at `/gateway` (and the `aiguard` CLI) that connects to Check Point management, checks the lab, creates a demo threat profile and rule after you approve the exact plan, runs scripted demo scenes through the gateway, and rolls everything back afterwards.
- **Auth & limits** — every page and API route requires sign-in (only `/login`, `/health` and static files are public); one admin account from `DEFAULT_ADMIN_EMAIL` plus `DEFAULT_ADMIN_PASSWORD` or `DEFAULT_ADMIN_PASSWORD_HASH`; sign-in limited to 10 attempts per minute; per-IP rate limiting (in-memory or Redis-backed).
- **API + docs** — JSON API under `/api/*` with an interactive Swagger UI at `/apidocs/` (sign-in required).

## Screenshots

_Screenshots to be added._

## Quick start

### Local (Python)

```bash
git clone https://github.com/alshawwaf/ai-guardrails-demo.git
cd ai-guardrails-demo

python -m venv venv && source venv/bin/activate   # Windows: .\venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env      # set DEFAULT_ADMIN_PASSWORD (or _HASH); add LAKERA_* and LLM keys as needed
python app.py             # http://127.0.0.1:9000
```

Sign in with `DEFAULT_ADMIN_EMAIL` and the password from `DEFAULT_ADMIN_PASSWORD` (or the one behind `DEFAULT_ADMIN_PASSWORD_HASH`). Sign-in is refused, with a message saying why, until those are set; the old published default `change_me_please` is refused too. There is no seeding step and no database user.

On first start the app creates `instance/.flask_secret` and `instance/.settings_key` (mode 0600) if `FLASK_SECRET_KEY` and `SETTINGS_ENCRYPTION_KEY` are not set, and logs a warning. Back up `instance/.settings_key` (or your `SETTINGS_ENCRYPTION_KEY`): saved API keys cannot be decrypted without it.

### Local (Docker)

```bash
docker build -t ai-guardrails-demo .
docker run -p 9000:9000 --env-file .env ai-guardrails-demo
```

## Gateway Mode and the aiguard CLI

Gateway Mode demonstrates **Check Point AI Agent Security**: a Threat Prevention blade on an R82.20 gateway that reads prompts sent to developer AI APIs (api.openai.com, api.anthropic.com, generativelanguage.googleapis.com and others) inside HTTPS Inspection, checks them with the AI Guardrails service, and blocks prompt injection, jailbreaks, sensitive data and (optionally) harmful content before they leave the network. The block shows up in SmartConsole Logs like any other Threat Prevention event.

The **AI Guard Demo Kit** (`aiguard/`, Python 3.8+, standard library only) does the lab work for you:

1. **Connect** to the Security Management Server or Multi-Domain Server through the Management API (TLS always verified).
2. **Preflight**: twelve read-only checks (management and gateway version, HTTPS Inspection, outbound CA, whether the provider traffic is really inspected, the route from this computer, the policy package, and whether the last policy installation on the gateway succeeded for both Access Control and Threat Prevention). Each problem comes with the exact fix. The install check (`last_install`) never blocks, but read it: after a partial install (Threat Prevention installed, Access Control failed) the gateway silently keeps enforcing the old Access Control policy, including the old HTTPS Inspection rules.
3. **Plan**: a threat profile with AI Agent Security on (your Guard API key and project ID), a threat rule at the top of the Threat Prevention layer that applies only to this computer by default, publish and install, and optionally content moderation on the gateway. Nothing is written until you type `APPROVE` for that exact plan id.
4. **Demo**: guided scenes (everyday work, prompt injection, personal data, content moderation, your own prompt) sent through the gateway, each result matched to its SmartConsole log.
5. **Rollback**: one command (or one click) removes everything the kit created, turns moderation off again, publishes and reinstalls.

You need: R82.20 management (Management API 2.2) and an R82.20 gateway, an AI Guardrails license, management connected to the Check Point Portal, a Guard API key (64 hex characters) and project ID from Check Point Portal > AI Security > AI Guardrails, HTTPS Inspection in Full mode with the outbound CA trusted by the demo computer, Management API access from the demo computer, a management server certificate that verifies (see below), and a demo computer whose traffic goes through the gateway. Behind NAT or in Docker, tell the kit the address the gateway sees: `--local-ip <ip>` (CLI) or `AIGUARD_LOCAL_IP` (CLI and web console). The full checklist and lab setup are in **[docs/GATEWAY_MODE.md](docs/GATEWAY_MODE.md)**; the presenter script is **[demo_guides/06_Gateway_Mode_AI_Agent_Security.md](demo_guides/06_Gateway_Mode_AI_Agent_Security.md)**.

> **The management server's TLS certificate must verify.** The kit (CLI and web console) always checks the certificate and the host name and has no option to skip that. The default Gaia portal certificate is self-signed and names the management IP only as its Common Name, with no Subject Alternative Name, so connecting to it **by IP address fails even when you trust it** with `--ca-file`. Sort this out before the demo day: issue an ICA-signed portal certificate with the IP and host name as SANs (sk164382) and pass the ICA certificate with `--ca-file` (web console: Connect > Certificate trust > Management CA certificate), or connect by the name in the certificate, or keep the IP and give that name with `--server-name` (web console: Name in the certificate) together with `--ca-file`. Compare the fingerprint the kit prints with `api fingerprint` on the server. Details: [docs/GATEWAY_MODE.md, 4.4](docs/GATEWAY_MODE.md#44-management-server-certificate).

### CLI

The CLI runs from the repository with any Python 3.8+ (no `pip install` needed), or `pip install .` puts an `aiguard` command on your PATH.

```bash
# Secrets never go on the command line: type them at a hidden prompt, or name an environment variable.
read -rs AIGUARD_MGMT_KEY && export AIGUARD_MGMT_KEY        # PowerShell: $env:AIGUARD_MGMT_KEY = Read-Host -MaskInput

python -m aiguard setup                                      # guided wizard [1/6]..[6/6]
python -m aiguard preflight --server 10.1.1.101 --server-name mgmt.lab.local \
    --ca-file ~/lab/mgmt-ca.pem --api-key-env AIGUARD_MGMT_KEY --gateway HQ-GW
python -m aiguard demo --guided                              # presenter mode
python -m aiguard rollback                                   # undo the latest change on this server
python -m aiguard --help                                     # every command and flag
```

Commands: `setup`, `preflight`, `plan`, `apply`, `demo`, `rollback`, `logs`, `fix https-inspection`, `trust-ca`, `status`, `version`. Exit codes: `0` ok, `1` a demo prompt did not do what was expected, `2` blocking preflight result or not supported, `3` an error (shown as What failed / Server said / Why / Fix / State / Details), `130` Ctrl-C (the open management session is discarded first). Run logs, reports and rollback points go to `~/.aiguard` (or `--home` / `AIGUARD_HOME`). `make aiguard-test` runs the kit's tests.

### Web console

Sign in and open **Gateway Mode** in the top navigation (`/gateway`). The steps are Connect, Preflight, Configure, Approve and install, Run the demo, Logs and report. Approval needs the box ticked and `APPROVE` typed; the server checks the plan id again before it writes anything. Provider keys and the Lakera key saved on the Settings page are reused (decrypted in memory only). Management credentials and the Guard API key are held in memory for that browser session only and are dropped after 60 minutes without activity.

Gateway Mode keeps those sessions in the memory of one app process: run **one** process (`python app.py`, which the Docker image does, or gunicorn with `-w 1 --threads 8`). Its run logs, reports and rollback points go to `AIGUARD_HOME`, by default `logs/aiguard/` in the app folder (the `./logs` volume in Docker).

### Lab quick start: a Linux host behind the gateway

One file, one command. On your workstation build the self-extracting installer (it contains this repository without git history, tests, settings or keys):

```bash
./scripts/make_lab_installer.sh          # writes dist/aiguard-lab-install.sh and prints its SHA-256
```

Copy `dist/aiguard-lab-install.sh` to the lab's Linux host (Ubuntu/Debian, behind the gateway) and run:

```bash
bash aiguard-lab-install.sh --mgmt <management-ip> --gateway <gateway-object-name>
```

It installs what is missing (Docker, curl, openssl), finds the gateway's HTTPS Inspection outbound CA and trusts it on the host and in the image (only when that CA validates the chain the gateway presents; fingerprints are printed for you to compare), writes `.env` with a generated admin password and app keys, checks the management server's certificate and whether its Management API accepts calls from the host, builds and starts the web console, and prints the URL and sign-in. The Connect page is then pre-filled (server, certificate, gateway); you type only the Management API key and the Guard API key + project ID, which stay in memory. Rerun the same file to update (settings and data are kept); `--uninstall` removes the container and image; `--help` lists the options. Verification is never turned off: when the management certificate cannot be verified by IP (the default Gaia certificate), the installer says so and how to fix it.

Manual alternative: `./scripts/lab_run_web.sh` builds and starts the same container from a checkout (put the outbound CA in `certs/outbound-ca.crt` first; see [docs/GATEWAY_MODE.md, 4.10](docs/GATEWAY_MODE.md#410-run-the-web-console-on-a-linux-host-behind-the-gateway)). The CLI runs in the same container and shares logs and rollback points: `sudo docker exec -it aiguard-web python -m aiguard setup`.

## Deployment

In production this app deploys automatically as part of the [Dev Hub](https://github.com/alshawwaf/dev-hub) suite via the [ubuntu-dokploy-ai](https://github.com/alshawwaf/ubuntu-dokploy-ai) installer, and is served at **guardrails.&lt;your-domain&gt;** behind Traefik.

For a full self-hosted stack with Redis-backed rate limiting, use the top-level compose files:

```bash
docker compose up -d                                                   # web (port 9000) + Redis + Redis Commander
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d  # production: + Nginx (port 80) + daily DB backup (or: make prod)
```

| Service | Description | Port |
|---------|-------------|------|
| `web` | The Flask application (one process: Gateway Mode needs that) | `9000`; with `docker-compose.prod.yml` `127.0.0.1:9000` only |
| `redis` | Distributed rate-limit store (no password) | `127.0.0.1:6380` → `6379` |
| `redis-commander` | Redis web UI (no sign-in) | `127.0.0.1:8082` |
| `nginx` | Reverse proxy, plain HTTP; a TLS server block is ready to uncomment in `nginx/nginx.conf` (`docker-compose.prod.yml`) | `80` / `443` |
| `backup` | Daily SQLite backup (`docker-compose.prod.yml`) | — |

Redis and Redis Commander are published on the Docker host's loopback only, because neither asks for credentials. `docker-compose-dev.yml` builds the image locally and runs gunicorn (one worker, eight threads) with live reload under its own project name.

**Behind nginx (`docker-compose.prod.yml`).** Every request then reaches the app from the nginx container, so the production file makes the app trust exactly one proxy (`TRUSTED_PROXY_HOPS=1`): the sign-in limit (10 attempts per minute) and the "Failed sign-in from" log lines then count each client by the address nginx appends to `X-Forwarded-For`, instead of one shared count for everyone. It also publishes the app port on the host's loopback only, because a client that could reach port 9000 directly could send its own `X-Forwarded-For` and choose the address the limit counts. Users come in on port 80 (443 with TLS); `make health` and `curl http://localhost:9000/health` still work on the Docker host.

- Needs Docker Compose 2.24.4 or later (`docker compose version`). Check once with `docker compose -f docker-compose.yml -f docker-compose.prod.yml config web`: one port with `host_ip: 127.0.0.1`, and `TRUSTED_PROXY_HOPS: "1"`. `make check-deploy` checks the files.
- To make every plain `docker compose` command on that host use both files, put `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml` in `.env` (`;` instead of `:` on Windows). Otherwise a later `docker compose up -d` recreates `web` without the production settings while nginx keeps running.
- Leave `TRUSTED_PROXY_HOPS=0` in `.env` for Docker Compose. Set it yourself only for your own proxy in front of the app (for example Traefik), and only when nothing but that proxy can reach the app port.
- The old `docker compose --profile production up -d` no longer starts nginx: the profile is gone. Stop an older production stack with `docker compose -f docker-compose.yml -f docker-compose.prod.yml down` (or `make stop`) before starting the new one.
- On Docker Desktop (macOS, Windows) published ports go through a user-space proxy, so containers may see one address for every client and the sign-in limit is then shared. Check the "Failed sign-in from" lines in `logs/application.log`.

A `Makefile` wraps the common flows — `make dev`, `make prod`, `make logs`, `make health`, `make backup`, `make test`, `make check-deploy`, `make aiguard-test`; run `make help` for the full list. See [docs/PRODUCTION.md](docs/PRODUCTION.md) and [docs/PRODUCTION_GUIDE.md](docs/PRODUCTION_GUIDE.md) for the full production path.

> **Gateway Mode in Docker:** with bridge networking the gateway sees the Docker host's address, not the container's. Set `AIGUARD_LOCAL_IP` in `.env` to the Docker host's IP as the gateway sees it (or fill in Connect > Network address translation in the console): the demo host object, the default `client` rule scope and the log matching then use that address. Without it, pick scope **Any** or an existing host object in Configure, or run the app directly on the demo computer. The Docker host's traffic to the AI providers must go through the gateway, and the container must trust the gateway's outbound CA (upload it on the Preflight page).

## Configuration

Set these in `.env` (see [.env.example](.env.example) and [docs/CONFIGURATION.md](docs/CONFIGURATION.md)). `.env.example` contains no working secrets: secret lines are empty or commented out (`set-me`).

**Sign-in and secrets**

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DEFAULT_ADMIN_EMAIL` | Admin sign-in email | Yes | — (sign-in refused) |
| `DEFAULT_ADMIN_PASSWORD` | Admin password. `change_me_please` is refused | Yes, unless `_HASH` is set | — (sign-in refused) |
| `DEFAULT_ADMIN_PASSWORD_HASH` | werkzeug password hash; used instead of the plain password. Put it in single quotes in `.env` | No | — |
| `FLASK_SECRET_KEY` | Session signing key (`python -c "import secrets;print(secrets.token_hex(32))"`), at least 32 characters. Published placeholders and shorter values are ignored with a warning | Recommended | generated `instance/.flask_secret` |
| `SETTINGS_ENCRYPTION_KEY` | AES-256-GCM key for saved API keys: base64 of 32 random bytes (`python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`) | Recommended | generated `instance/.settings_key` |
| `SESSION_COOKIE_SECURE` | `true` when users reach the app over HTTPS | No | `false` |
| `TRUSTED_PROXY_HOPS` | Number of reverse proxies in front of the app whose `X-Forwarded-For` / `-Proto` / `-Host` / `-Port` headers are trusted, so the sign-in limit and the sign-in log see the real client IP. `0` when users reach the app port directly. `docker-compose.prod.yml` sets `1` for its nginx by itself; set it yourself only for your own proxy, and only when nothing else can reach the app port (a direct client could otherwise forge `X-Forwarded-For`) | No | `0` (`1` in `docker-compose.prod.yml`) |
| `FLASK_DEBUG` | Werkzeug debugger and reloader, only with `1` or `true` | No | off |

**Guardrails and LLM providers** (the Settings page overrides these)

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `LAKERA_API_KEY` | AI Guardrails (Lakera Guard) API key (`DEMO_API_KEY` is read first if set) | For the Playground (or set it on Settings) | — |
| `LAKERA_PROJECT_ID` | AI Guardrails project ID (`DEMO_PROJECT_ID` is read first) | No (empty uses the default policy) | — |
| `LAKERA_API_URL` | Guard endpoint including `/v2/guard` (`DEMO_API_URL` wins if set) | No | `https://api.lakera.ai/v2/guard` |
| `OPENAI_API_KEY` | OpenAI API key | No | — |
| `OPENAI_API_URL` | OpenAI chat-completions endpoint | No | `https://api.openai.com/v1/chat/completions` |
| `ANTHROPIC_API_KEY` | Anthropic API key | No | — |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | No | — |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL, `https://` only (an `http://` value is not used) | No | — |
| `AZURE_OPENAI_DEPLOYMENT` | Azure deployment name | No | `gpt-4o-mini-2024-07-18` |
| `GEMINI_API_KEY` | Google Gemini API key | No | — |
| `OLLAMA_API_URL` | Ollama base URL (local LLM) | No | `http://ollama-cpu:11434` (`.env.example` sets `http://localhost:11434`) |
| `OLLAMA_TIMEOUT` | Ollama request timeout (s) | No | `120` |
| `OLLAMA_MODEL` | Default local target model | No | see `.env.example` |
| `DEFAULT_LLM_PROVIDER` | Playground default provider | No | `ollama` |
| `DEFAULT_LLM_MODEL` | Playground default model | No | see `.env.example` |
| `AZURE_CONTENT_SAFETY_KEY` | Azure AI Content Safety key (benchmarking) | No | — |
| `AZURE_CONTENT_SAFETY_ENDPOINT` | Azure AI Content Safety endpoint (benchmarking), `https://` only | No | — |

**Application**

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `APP_PORT` | Application port | No | `9000` |
| `CORS_ORIGINS` | Explicit origins allowed to call `/api/*` cross-origin, comma-separated. `*` is ignored with a warning. Listed origins get credentials (call with `credentials: 'include'`); because the session cookie is `SameSite=Lax` this works only for same-site origins, cross-site callers get `401` | No | empty (CORS off) |
| `APP_ORIGIN` | The app's public origin(s), exact (scheme, host, port), comma-separated, for example `https://demo.example.com`. Only needed behind a reverse proxy that drops the public port or scheme (or sends no `X-Forwarded-*`); otherwise the origin is worked out per request. A refused POST is logged with a hint to set `TRUSTED_PROXY_HOPS` or `APP_ORIGIN` | No | empty |
| `RATE_LIMIT_DAILY` | Requests/day per IP | No | `1000000` |
| `RATE_LIMIT_HOURLY` | Requests/hour per IP | No | `100000` |
| `RATE_LIMIT_STORAGE` | Rate-limit backend (`memory://` or `redis://…`) | No | `memory://` |
| `LOGS_DIR` / `LOG_FILENAME` | Application log location | No | `logs` / `application.log` |
| `INSTANCE_DIR` | Folder for the SQLite DB and generated key files | No | `./instance` |
| `DB_PATH` / `DATABASE_URL` | SQLite file / full SQLAlchemy URL | No | `instance/demo_logs.db` |
| `MAX_CONTENT_LENGTH` | Largest request body in bytes | No | `2097152` |
| `AIGUARD_HOME` | Gateway Mode run logs, reports, rollback points (no secrets) | No | web: `logs/aiguard`; CLI: `~/.aiguard` |
| `AIGUARD_LOCAL_IP` | This computer's (or the Docker host's) IP as the gateway sees it, for the demo rule's scope and log matching behind NAT | No | detected |

> The rate-limit defaults are intentionally high: when embedded in the Dev Hub desktop (iframe) a single session generates many requests, so a low limit trips instantly and breaks the demo. `GUNICORN_THREADS` and `GUNICORN_TIMEOUT` are used by `docker-compose-dev.yml`; the Docker image itself runs `python app.py`. Keep gunicorn at one worker when Gateway Mode is used.

You can also set API keys, the default provider/model, and local model preferences at runtime from the in-app **Settings** page (persisted to SQLite, API keys encrypted).

## Security notes

- **Sign-in everywhere.** A global check sends unauthenticated page requests to `/login` and answers API calls (`/api/*`, `/gateway/api/*`, `/apispec_1.json`) with `401 {"error": "Sign in required"}`. Only `/login`, `/health` and static files are public.
- **Cross-site requests are refused.** POST, PUT, PATCH and DELETE requests whose `Origin` (or `Referer`) is not exactly this app's origin (scheme, host and port) get `403`. Behind a reverse proxy the app learns its public origin from `X-Forwarded-Proto` / `-Host` / `-Port`; if your proxy sends none of them, list the public origin in `APP_ORIGIN`. Session cookies are `HttpOnly` and `SameSite=Lax`; set `SESSION_COOKIE_SECURE=true` behind HTTPS. Because of `SameSite=Lax`, embedding the app in an iframe on a different site (for example a Dev Hub on another domain) will not keep you signed in; serve both from the same site.
- **Secrets at rest.** API keys saved on the Settings page are encrypted with AES-256-GCM bound to the setting's name (`enc:v2:` values in the `settings` table); the Azure endpoint URLs stay readable with an integrity tag (`mac:v1:`). Rows saved by an older version are upgraded once at startup, recorded in `instance/.settings_format`; after that, older-format rows are ignored. After an upgrade from plaintext, rotate those keys and delete older backups (the startup log says so). SQLite `secure_delete` is on, the file is compacted after the upgrade and kept at mode 0600; backups are 0600 in a 0700 folder. `/api/settings` and the Settings page return only "configured" flags (for example `guardrails_key_configured`) and masked hints. Details: [docs/CONFIGURATION.md, Secrets and Saved Settings](docs/CONFIGURATION.md#secrets-and-saved-settings).
- **Content-Security-Policy.** Every page allows scripts from the app's origin only. Chart.js is pinned to one jsDelivr file and loaded only on the Playground, Dashboard and Benchmarking pages; put `chart.umd.js` at `static/vendor/chart.umd.js` to serve it yourself (the CSP then allows no CDN at all).
- **Generated keys.** `instance/.flask_secret` and `instance/.settings_key` are created with mode 0600. The `instance/` folder is excluded from git and from the Docker image; keep it private and backed up.
- **Logs.** `application.log` records prompts only as length, a short hash and a redacted 60-character preview. The Gateway Mode run logs mask every key and session id (`****` plus the last four characters) and every password (`****` only).
- **Gateway Mode.** TLS verification is never turned off: trust is extended only with a CA file you provide. Management credentials and the Guard API key live in memory only. Nothing changes on the management server until a plan is approved, a rollback point is saved before publishing, and the demo rule applies only to the demo computer by default. Details: [docs/GATEWAY_MODE.md, Security model](docs/GATEWAY_MODE.md#security-model).
- **Debug mode** is off unless `FLASK_DEBUG=1`. Do not enable it on a host other people can reach.
- **Redis** has no password; the compose file publishes it, and Redis Commander, on the host loopback only.
- **Sign-in limit and proxies.** `/login` allows 10 sign-in attempts per minute per client address. The app reads the address from `X-Forwarded-For` only when `TRUSTED_PROXY_HOPS` is set; `docker-compose.prod.yml` sets it to `1` for its nginx and keeps the app port on loopback so the header cannot be forged by a direct client. nginx sets `X-Forwarded-Proto` and `X-Forwarded-Host` itself, removes any `X-Forwarded-Port` a client sent, and appends to `X-Forwarded-For` in every location.

## Tech stack

- **Backend** — Flask, Flask-SQLAlchemy (SQLite), Flask-Login, Flask-Limiter, Flask-CORS (only when `CORS_ORIGINS` is set), Flasgger (Swagger), Gunicorn, `cryptography` (AES-256-GCM for saved keys).
- **Frontend** — vanilla ES6 JavaScript modules, modular CSS (`base` / `components` / `pages`), Chart.js — no framework.
- **Detection & LLMs** — Lakera Guard (guardrail engine); OpenAI, Azure OpenAI, Anthropic, Google Gemini, Ollama (target LLMs); Azure AI Content Safety and LLM Guard (benchmarking).
- **Gateway Mode** — `aiguard`, standard-library Python 3.8+ (no third-party packages): Check Point Management API client, preflight, plans, demo traffic, log correlation, reports.
- **Ops** — Docker, Redis, Nginx; CPU-only PyTorch in the image (LLM Guard models cached in a `models_cache` volume, lazy-loaded).

## Project structure

```
ai-guardrails-demo/
├── app.py                  # Flask app: routes, DB models, guard/scan pipeline, sign-in gate
├── secure_settings.py      # AES-256-GCM encryption of saved API keys
├── aiguard/                # AI Guard Demo Kit core + CLI (stdlib only): python -m aiguard
│   └── templates/          #   data-driven plan templates (JSON)
├── gateway_mode/           # Flask blueprint for the Gateway Mode console (/gateway)
├── pyproject.toml          # packaging for the aiguard CLI only (pip install .)
├── Dockerfile              # Python 3.11-slim, CPU-only torch; trusts any certs/*.crt
├── certs/                  # optional extra CA certificates for the image (e.g. the gateway's outbound CA; *.crt git-ignored)
├── docker-compose.yml      # Full stack: web + Redis + Redis Commander
├── docker-compose.prod.yml # Production: + Nginx + backup; app behind nginx (TRUSTED_PROXY_HOPS=1, port on loopback)
├── docker-compose-dev.yml  # Local build with gunicorn --reload
├── Makefile                # Task automation (make help)
├── data/triggers.json      # Attack trigger library
├── demo_guides/            # Per-page demo walkthroughs (06: Gateway Mode)
├── docs/                   # ARCHITECTURE / CONFIGURATION / PRODUCTION / DEVELOPER_GUIDE / GATEWAY_MODE
├── nginx/nginx.conf        # Reverse-proxy config (docker-compose.prod.yml)
├── scripts/                # make_lab_installer.sh + lab_install.sh (one-command lab installer), lab_run_web.sh (build + run), start_production.sh, backup_db.py, warmup_models.py, check_deploy_config.py
├── static/                 # ES6 JS modules + modular CSS
├── templates/              # Jinja2 templates (templates/gateway/: Gateway Mode pages)
└── tests/                  # pytest suite (tests/core: aiguard, no heavy dependencies)
```

> `instance/` (SQLite DB and generated keys), `logs/` (including `logs/aiguard/`), `backups/`, and `models_cache/` are created at runtime and git-ignored.

## API

Interactive docs live at `/apidocs/` while the app is running. Every endpoint except `/health` requires a signed-in session. Key endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness check (public, rate-limit exempt) |
| `POST` | `/api/analyze` | Run a prompt through inbound → LLM → outbound |
| `GET` / `DELETE` | `/api/logs` | List (paginated) / clear logs (`/api/logs/<id>` deletes one) |
| `GET` | `/api/logs/export/{json,csv}` | Export logs |
| `GET` | `/api/analytics` | Dashboard analytics |
| `GET` | `/api/triggers` | List attack triggers |
| `POST` | `/api/scan/{guardrails,azure,llmguard}` | Single-engine scans |
| `POST` | `/api/compare` | Compare a prompt across all three engines |
| `GET` | `/api/benchmark/{history,stats}` | Benchmarking data |
| `GET`/`POST` | `/api/models/{status,toggle,download}` | Local LLM Guard model management |
| `GET`/`POST` | `/gateway/api/*` | Gateway Mode console (JSON bodies, same-origin; see [docs/GATEWAY_MODE.md](docs/GATEWAY_MODE.md#web-console)) |

## Development

```bash
python -m pytest tests/core -q   # aiguard core: fast, needs only pytest + cryptography (or: make aiguard-test)
python -m pytest tests/          # everything (or: make test); app tests need requirements.txt
```

`tests/conftest.py` stubs the heavy optional modules (torch/transformers, llm_guard, Azure, google-genai, flasgger, flask_cors) when they are not installed, so the app tests also run in a light environment.

- **Python** — PEP 8. `aiguard/` stays standard-library only with Python 3.8-compatible syntax.
- **JavaScript** — ES6+, 4-space indentation. Put user, prompt, LLM and log data into the page with `textContent` or `escapeHtml`, never raw `innerHTML`.
- **CSS** — modular, split across `static/css/{base,components,pages}`.
- **Templates** — files under `templates/` are Jinja2; disable HTML auto-format for them (spaces inside `{{ }}` break the syntax).

CI runs on GitHub Actions (`.github/workflows/ci.yml`): the aiguard core tests on several Python versions, pytest + flake8 for the app, the reverse-proxy and port checks (`scripts/check_deploy_config.py` on what Docker Compose resolves), a Trivy filesystem scan (pinned action), and — on pushes to `main` — a Docker image build pushed to GHCR. See the [Developer Guide](docs/DEVELOPER_GUIDE.md) and [Architecture Overview](docs/ARCHITECTURE.md) for details.

## License

Released under the [MIT License](LICENSE).
