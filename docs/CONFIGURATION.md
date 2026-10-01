# Configuration Reference

## Environment Variables

All application settings can be configured via environment variables in the `.env` file.

### AI Guardrails Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LAKERA_API_KEY` | AI Guardrails API authentication key | - | Yes |
| `LAKERA_PROJECT_ID` | AI Guardrails project identifier | - | Yes |
| `LAKERA_API_URL` | AI Guardrails API endpoint | `https://api.lakera.ai/v2/guard` | No |

### LLM Provider Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key | - | No |
| `OPENAI_API_URL` | OpenAI API endpoint | `https://api.openai.com/v1/chat/completions` | No |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | - | No |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL. Must be `https://` (an `http://` value is ignored with a warning: the key is sent in a header) | - | No |
| `AZURE_OPENAI_DEPLOYMENT` | Azure deployment name | `gpt-4o-mini-2024-07-18` | No |
| `GEMINI_API_KEY` | Google Gemini API key | - | No |
| `AZURE_CONTENT_SAFETY_KEY` | Azure AI Content Safety key (Benchmarking page) | - | No |
| `AZURE_CONTENT_SAFETY_ENDPOINT` | Azure AI Content Safety endpoint. Must be `https://`, like `AZURE_OPENAI_ENDPOINT` | - | No |

### Application Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `APP_PORT` | Application port number | `9000` | No |
| `LOGS_DIR` | Log file directory | `logs` | No |
| `LOG_FILENAME` | Log file name | `application.log` | No |

### CORS Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CORS_ORIGINS` | Explicit origins allowed to call `/api/*` from another site | empty (no CORS) | No |

`*` is ignored (the app logs a warning): list each origin explicitly.

Every `/api/*` route needs the signed-in session, so a listed origin is allowed
**with credentials** (`Access-Control-Allow-Credentials: true`) and must call
with `credentials: 'include'` (fetch) or `withCredentials` (XHR). The session
cookie is `SameSite=Lax`: browsers send it only from **same-site** origins
(another subdomain or port of the same site), never from another site, so a
cross-site caller gets `401` even when it is listed. `CORS_ORIGINS` cannot open
the API to other sites.

**Examples:**
- No cross-site API access (default): leave `CORS_ORIGINS` empty
- Single domain: `CORS_ORIGINS=https://example.com`
- Multiple domains: `CORS_ORIGINS=https://example.com,https://app.example.com`

### Reverse Proxy and Sign-in

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `TRUSTED_PROXY_HOPS` | Reverse proxies in front of the app whose `X-Forwarded-For` / `-Proto` / `-Host` / `-Port` headers are trusted (0 to 5) | `0` | No |
| `SESSION_COOKIE_SECURE` | `true` when users reach the app over HTTPS | `false` | No |
| `APP_ORIGIN` | The app's public origin(s), comma-separated exact origins (scheme, host and port), for example `https://demo.example.com`. For a proxy that drops the public port or scheme, or sends neither the browser's Host port nor `X-Forwarded-*` | empty (worked out per request) | No |

`/login` allows 10 sign-in attempts per minute per client address, and the
sign-in log lines record that address. The app reads it from
`X-Forwarded-For` only when `TRUSTED_PROXY_HOPS` is above 0:

- `0`: users reach the app port directly (`python app.py`, `docker run`,
  `docker compose up`). Behind a proxy with `0`, every user has the proxy's
  address and they all share one sign-in count.
- `1`: one proxy that sets `X-Forwarded-For`, and nothing else can reach the
  app port. `docker-compose.prod.yml` sets this for the bundled nginx by itself
  and publishes the app port on `127.0.0.1` only; keep `0` in `.env`.
- Never set it while the app port is reachable without the proxy: a direct
  client could send its own `X-Forwarded-For` and pick the address the limit
  counts.

The same hops also give the scheme, host and port the browser used
(`X-Forwarded-Proto`, `-Host`, `-Port`). POST, PUT, PATCH and DELETE requests
must come from exactly that origin, so the proxy must pass the browser's host
and port (nginx: `proxy_set_header X-Forwarded-Host $http_host;`) and should
remove a client-sent `X-Forwarded-Port`. When it cannot, set `APP_ORIGIN`.

A refused request is logged in `logs/application.log` ("Refused cross-origin
... (from X, this app is Y)") with a hint to set `TRUSTED_PROXY_HOPS` or
`APP_ORIGIN`; the browser gets `403`.

### Secrets and Saved Settings

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FLASK_SECRET_KEY` | Signs the session cookie. At least 32 characters (`python -c "import secrets;print(secrets.token_hex(32))"`). A shorter value, or a published placeholder, is ignored with a startup warning | empty: `instance/.flask_secret` is generated (mode 0600) | No |
| `SETTINGS_ENCRYPTION_KEY` | Base64 of exactly 32 random bytes: the AES-256-GCM key for the API keys saved on the Settings page. Back it up; a malformed value stops the app | empty: `instance/.settings_key` is generated (mode 0600) | No |

How the Settings page stores values (`instance/demo_logs.db`):

- **API keys**: `enc:v2:<nonce>:<ciphertext>`, AES-256-GCM with the setting's
  name bound to it, so a value copied into another row does not decrypt.
- **Azure endpoints** (`AZURE_OPENAI_ENDPOINT`, `AZURE_CONTENT_SAFETY_ENDPOINT`):
  readable, with an integrity tag bound to the name (`mac:v1:<tag>:<value>`),
  so a URL written into the database by someone else is not used.
- **Upgrade, once**: on the first start of this version, rows saved by older
  versions (plaintext keys, `enc:v1`, untagged endpoints) are upgraded and
  `instance/.settings_format` records that the upgrade ran. It never runs
  again: from then on a row in an older format is reported at startup and
  ignored (treated as not set), never upgraded, because the app cannot tell a
  legacy row from one planted later.
- **Restoring a backup** made before the upgrade: its saved keys are ignored
  until you enter them again on the Settings page, or until you delete
  `instance/.settings_format` and restart (the upgrade then runs once more).
- **After upgrading from plaintext**: the startup log says how many keys were
  stored in plaintext. Rotate those keys at their providers and delete the
  backups taken before the upgrade (they still hold the plaintext values).
- SQLite `secure_delete` is on, so replaced or cleared values are overwritten
  in the file; after the upgrade the file is `VACUUM`ed, and the database file
  is kept owner-only (mode 0600). `scripts/backup_db.py` creates `backups/`
  with mode 0700 and each backup with mode 0600.
- `GET /api/settings` never returns a saved key, only masked hints and
  booleans. `guardrails_key_configured` is true when an AI Guardrails (Lakera)
  key is available from Settings or the environment (scans need only the key);
  `guardrails_configured` also needs the project ID.

### Pages: Chart.js and Content-Security-Policy

Every HTML page is sent with a `Content-Security-Policy` that allows scripts
from the app's own origin only (`script-src 'self'`; Swagger UI at `/apidocs/`
is the one exception). Chart.js is pinned to one file,
`https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js`, and is loaded
only on the pages that draw charts (Playground, Dashboard, Benchmarking), never
where keys or passwords are typed (Settings, sign-in, Gateway Mode); the CSP of
those chart pages adds exactly that URL.

To serve it yourself (no CDN at all, for example on an isolated network), put a
copy of `chart.umd.js` at `static/vendor/chart.umd.js`: the app then uses it
and the chart pages' CSP allows only the app's own origin.

### Rate Limiting Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RATE_LIMIT_DAILY` | Maximum requests per day per IP | `1000000` | No |
| `RATE_LIMIT_HOURLY` | Maximum requests per hour per IP | `100000` | No |
| `RATE_LIMIT_STORAGE` | Rate limit storage backend | `memory://` | No |

**Storage Options:**
- **Development**: `memory://` (in-memory, resets on restart)
- **Production**: `redis://localhost:6379` (persistent, shared across instances)

**Examples:**
```env
# Stricter limits
RATE_LIMIT_DAILY=100
RATE_LIMIT_HOURLY=25

# Production with Redis
RATE_LIMIT_STORAGE=redis://redis:6379/0
```

### Production Server Configuration (Gunicorn)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GUNICORN_WORKERS` | Number of worker processes. Keep `1` when Gateway Mode is used (its sessions live in one process's memory); use threads for concurrency | `1` | No |
| `GUNICORN_TIMEOUT` | Request timeout in seconds | `120` | No |
| `GUNICORN_BIND` | Bind address and port | `0.0.0.0:9000` | No |

**Workers and threads:**
```bash
# Gateway Mode keeps each signed-in user's management session in memory:
# run ONE worker and scale with threads.
GUNICORN_WORKERS=1
GUNICORN_THREADS=8
```

**Timeout Considerations:**
- LLM API calls can be slow (5-30 seconds typical)
- Add buffer for network latency
- Default 120s accommodates most scenarios
- Increase for complex multi-step operations

## Configuration Examples

### Development Environment

```env
# .env.development
APP_PORT=9000
CORS_ORIGINS=
RATE_LIMIT_DAILY=1000
RATE_LIMIT_HOURLY=200
RATE_LIMIT_STORAGE=memory://
GUNICORN_WORKERS=1
```

### Staging Environment

```env
# .env.staging
APP_PORT=9000
CORS_ORIGINS=https://staging.example.com
RATE_LIMIT_DAILY=500
RATE_LIMIT_HOURLY=100
RATE_LIMIT_STORAGE=redis://redis:6379/0
GUNICORN_WORKERS=1
GUNICORN_THREADS=8
GUNICORN_TIMEOUT=120
```

### Production Environment

```env
# .env.production
APP_PORT=9000
CORS_ORIGINS=https://example.com,https://app.example.com
RATE_LIMIT_DAILY=200
RATE_LIMIT_HOURLY=50
RATE_LIMIT_STORAGE=redis://redis:6379/0
GUNICORN_WORKERS=1
GUNICORN_THREADS=8
GUNICORN_TIMEOUT=180
GUNICORN_BIND=0.0.0.0:9000
```

## Docker Configuration

### Single Instance

```yaml
# docker compose.yml
services:
  web:
    environment:
      - GUNICORN_WORKERS=1
      - RATE_LIMIT_STORAGE=memory://
```

### Multi-Instance with Redis

```yaml
# docker compose.yml
services:
  web:
    environment:
      - GUNICORN_WORKERS=1
      - RATE_LIMIT_STORAGE=redis://redis:6379/0
    # Several replicas work for the playground pages only: Gateway Mode
    # sessions are per process, so use sticky sessions or a single replica.
    deploy:
      replicas: 3

  redis:
    image: redis:7-alpine
    # No password: publish it on loopback only (or not at all).
    ports:
      - "127.0.0.1:6379:6379"
```

## Security Best Practices

1. **Never commit `.env` files** - Use `.env.example` as template
2. **Restrict CORS in production** - Specify exact domains
3. **Use Redis for rate limiting** - Enables distributed rate limiting
4. **Adjust limits based on usage** - Monitor and tune as needed
5. **Keep secrets secure** - Use secret management tools in production
6. **Rotate API keys regularly** - Change keys periodically

## Troubleshooting

### Rate Limit Issues

```bash
# Check current configuration
docker exec <container> env | grep RATE_LIMIT

# Increase limits temporarily
RATE_LIMIT_HOURLY=100 docker compose up
```

### CORS Errors

```bash
# Verify CORS settings
docker exec <container> env | grep CORS

# Allow specific domain
CORS_ORIGINS=https://your-domain.com docker compose restart
```

### Performance Tuning

```bash
# More threads (keep ONE worker: Gateway Mode sessions live in that process).
# Used by docker-compose-dev.yml; the image itself runs "python app.py".
GUNICORN_THREADS=16 docker compose -f docker-compose-dev.yml up -d

# Longer timeout for slow APIs
GUNICORN_TIMEOUT=300 docker compose -f docker-compose-dev.yml up -d
```

### Everyone gets "Too many sign-in attempts"

Behind a reverse proxy with `TRUSTED_PROXY_HOPS=0` all users share the proxy's
address and one sign-in count (10 per minute). Check `logs/application.log`:
if every "Failed sign-in from" line shows the same address, start the bundled
nginx with `docker-compose.prod.yml` (it sets `TRUSTED_PROXY_HOPS=1`), or set
`TRUSTED_PROXY_HOPS` for your own proxy and keep the app port reachable only by
that proxy.

## Migration Guide

### From Hardcoded to Environment-Based

If upgrading from a previous version with hardcoded values:

1. **Copy example configuration**:
   ```bash
   cp .env.example .env
   ```

2. **Set your existing values**:
   - Review your old `app.py` for hardcoded values
   - Add equivalent environment variables to `.env`

3. **Test configuration**:
   ```bash
   python app.py
   # or
   docker compose up
   ```

4. **Verify settings**:
   - Check `/health` endpoint is accessible
   - Test rate limiting behavior
   - Verify CORS headers in API responses
