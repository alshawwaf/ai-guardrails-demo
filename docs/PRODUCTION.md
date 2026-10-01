# Production Deployment Guide

## Quick Start

### Using Docker Compose (Recommended)

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 2. Start the application (users reach port 9000 directly)
docker compose up -d
#    or behind the bundled Nginx on port 80 (see "Reverse Proxy Configuration")
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d    # make prod

# 3. Check health
curl http://localhost:9000/health
```

### Using Gunicorn Directly

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run with Gunicorn: ONE worker (Gateway Mode keeps sessions in memory), threads for concurrency
gunicorn -w 1 --threads 8 -b 0.0.0.0:9000 --timeout 120 app:app
```

## Production Checklist

- [ ] Configure all environment variables in `.env`
- [ ] Set `FLASK_SECRET_KEY` (at least 32 characters) and `SETTINGS_ENCRYPTION_KEY`, or keep the generated `instance/.flask_secret` / `instance/.settings_key`, and back up the settings key (saved API keys cannot be decrypted without it)
- [ ] Set `APP_PORT` if not using default 9000
- [ ] Configure API keys for AI Guardrails
- [ ] (Optional) Configure LLM providers
- [ ] Set up regular database backups
- [ ] Configure reverse proxy (nginx/Apache) and set `TRUSTED_PROXY_HOPS` to match it (`docker-compose.prod.yml` does this for the bundled nginx)
- [ ] Behind a proxy, make the app port reachable only by the proxy (bind `127.0.0.1` or firewall it)
- [ ] Enable HTTPS/SSL
- [ ] Set up monitoring and logging
- [ ] Configure firewall rules

## Database Backups

The application includes an automated backup script:

```bash
python scripts/backup_db.py
```

This will:
- Create a timestamped backup in `backups/` directory
- Keep the 10 most recent backups
- Remove older backups automatically
- Keep them owner-only: `backups/` is created with mode 0700 and each backup
  file with mode 0600 (existing backups are tightened on each run; on Windows
  protect the folder with its ACL)

Backups contain the saved Settings: API keys encrypted with the settings key
(`enc:v2`), so keep the settings key backed up separately. Backups made by an
older version, before the saved-settings upgrade, can contain the keys in
plaintext: after upgrading, rotate those keys and delete those backups. A
restored pre-upgrade database is not upgraded automatically (its saved keys are
ignored until you enter them again, or until you delete
`instance/.settings_format` and restart). See "Secrets and Saved Settings" in
[CONFIGURATION.md](CONFIGURATION.md).

### Automated Backups

Add to crontab for daily backups:
```cron
0 2 * * * cd /path/to/ai-guardrails-demo && python scripts/backup_db.py
```

## Monitoring

### Health Check Endpoint

```bash
curl http://localhost:9000/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-11-27T18:00:00.000000",
  "version": "1.0.0"
}
```

### Docker Health Check

The docker compose configuration includes automatic health checks:
- Interval: 30 seconds
- Timeout: 10 seconds
- Retries: 3
- Start period: 40 seconds

## Rate Limiting

The application includes rate limiting:
- **Default**: 1000000 requests per day, 100000 per hour per IP
- **Sign-in**: 10 attempts per minute per client address on `/login`
- **Storage**: In-memory (resets on restart); the compose stack uses Redis (`RATE_LIMIT_STORAGE=redis://redis:6379/0`)
- **Gateway Mode** (`/gateway/api/`): connect, MDS domain switch, Guard key check and apply are limited to 10 per minute per signed-in user and client address (`429` with `Retry-After`), using the same storage. The bundled nginx also limits `/gateway/api/` to 5 requests per second per address (burst 30), above what the console's job polling needs

Every limit counts by client address. Behind a reverse proxy the app sees the
proxy's address unless `TRUSTED_PROXY_HOPS` tells it how many proxies to trust;
with the default `0` all users behind the proxy share one sign-in count. See
[Reverse Proxy Configuration](#reverse-proxy-configuration).

## CORS Configuration

CORS is off by default. Set `CORS_ORIGINS` to a comma-separated list of explicit origins to allow cross-site calls to `/api/*`; `*` is ignored with a warning. State-changing requests from any other origin are refused with `403` either way.

Listed origins are allowed with credentials and must call with `credentials: 'include'`. The session cookie is `SameSite=Lax`, so this works only for same-site origins (another subdomain or port of the same site); a cross-site caller gets `401`.

## Stopping the App

`docker stop` (and `docker compose down`) sends SIGTERM, then SIGKILL after the
grace period. On SIGTERM the app runs its shutdown: Gateway Mode gives a running
publish or install up to 8 seconds, then discards what is still unpublished,
marks an interrupted change's rollback point "publish-unknown" (still
undoable) and logs out of the management server. `docker-compose.yml` sets
`stop_grace_period: 15s` and `init: true` for the web service; with a plain
`docker run`, use `--stop-timeout 15 --init`. Under gunicorn, SIGTERM is
gunicorn's: give it a graceful timeout of at least 15 seconds.

## Performance Tuning

### Gunicorn Workers

Run one worker and scale with threads: Gateway Mode keeps each signed-in user's management session in that process's memory, so a second worker would not know it.

```bash
gunicorn -w 1 --threads 8 -b 0.0.0.0:9000 app:app
```

### Timeout

Default timeout is 120 seconds for LLM API calls. Adjust if needed:

```bash
gunicorn -w 1 --threads 8 -b 0.0.0.0:9000 --timeout 180 app:app
```

## Reverse Proxy Configuration

The bundled Nginx runs with `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`
(`make prod`); that file sets `TRUSTED_PROXY_HOPS=1` for the app and publishes
the app port on loopback only. See [PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md#behind-nginx-client-addresses-and-the-sign-in-limit).

For a proxy of your own:

1. Set `TRUSTED_PROXY_HOPS` to the number of proxies in front of the app (`1`
   for one nginx or Apache). The app then reads the client address from the
   `X-Forwarded-For` entry the nearest trusted proxy appended, and the scheme,
   host and port from `X-Forwarded-Proto` / `X-Forwarded-Host` /
   `X-Forwarded-Port`. State-changing requests must come from exactly that
   origin (scheme, host and port).
2. Make the app reachable only through the proxy: bind it to `127.0.0.1`
   (`gunicorn -b 127.0.0.1:9000 ...`) or firewall the port. Otherwise a client
   that connects directly can send its own `X-Forwarded-For` and pick the
   address the sign-in limit counts.
3. Have the proxy set (not pass through) the forwarded headers, as below.
4. Behind HTTPS set `SESSION_COOKIE_SECURE=true`.

### Nginx Example

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;   # host and port the browser used
        proxy_set_header X-Forwarded-Port "";           # drop a client-sent value
    }
}
```

With `TRUSTED_PROXY_HOPS=1`. If your proxy cannot send the browser's host and
port, set `APP_ORIGIN` to the public origin (for example
`https://guardrails.example.com`).

### Apache Example

```apache
<VirtualHost *:80>
    ServerName your-domain.com
    
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9000/
    ProxyPassReverse / http://127.0.0.1:9000/
</VirtualHost>
```

Apache's `mod_proxy` adds `X-Forwarded-For` and `X-Forwarded-Host` itself; use
`TRUSTED_PROXY_HOPS=1`. It does not set `X-Forwarded-Proto` or remove
`X-Forwarded-Port`, which the app then also trusts, so add (mod_headers)
`RequestHeader set X-Forwarded-Proto "http"` (`"https"` on a TLS virtual host)
and `RequestHeader unset X-Forwarded-Port`.

## Security Recommendations

1. **Never commit `.env` file** - Already in `.gitignore`
2. **Use environment-specific configurations** - Separate `.env` for dev/staging/prod
3. **Enable HTTPS** - Use Let's Encrypt for free SSL certificates
4. **Restrict CORS** - Limit to your specific domains in production
   (same-site origins only, see above)
5. **API Rate Limiting** - Monitor and adjust limits based on usage
6. **Regular Updates** - Keep dependencies up to date
7. **Database Backups** - Automate daily backups
8. **Monitoring** - Set up alerts for health check failures
9. **Content-Security-Policy** - Sent on every page (scripts from the app's
   origin only; the chart pages add the one pinned Chart.js file). To avoid
   the CDN, put `chart.umd.js` at `static/vendor/chart.umd.js`

## Troubleshooting

### Health Check Fails

```bash
# Check if application is running
docker compose ps

# View logs
docker compose logs -f web

# Restart service
docker compose restart web
```

### Database Issues

```bash
# Check database file exists
ls -lh instance/demo_logs.db

# Restore from backup (stop the app first; keep the file owner-only)
cp backups/demo_logs_backup_YYYYMMDD_HHMMSS.db instance/demo_logs.db
chmod 600 instance/demo_logs.db
```

### High Memory Usage

```bash
# Fewer threads (keep ONE worker: Gateway Mode sessions live in that process)
gunicorn -w 1 --threads 4 -b 0.0.0.0:9000 app:app

# Or limit memory in docker-compose.yml
services:
  web:
    deploy:
      resources:
        limits:
          memory: 512M
```
