# Full Environment Guide

This guide covers the multi-service deployment defined in the top-level
[`docker-compose.yml`](../docker-compose.yml) and, for the production stack
behind Nginx, [`docker-compose.prod.yml`](../docker-compose.prod.yml). For a minimal
single-container / Gunicorn deployment and the production checklist, see
[PRODUCTION.md](PRODUCTION.md).

## Services

| Service | File | Notes |
|---------|------|-------|
| `web` | `docker-compose.yml` | Main Flask application on port `9000`. Container entrypoint is `scripts/start_production.sh`. `docker-compose.prod.yml` publishes it on `127.0.0.1:9000` only and sets `TRUSTED_PROXY_HOPS=1`. |
| `redis` | `docker-compose.yml` | Redis 7 (appendonly) for distributed rate limiting. Host port `127.0.0.1:6380` → container `6379`. |
| `redis-commander` | `docker-compose.yml` | Redis web UI at <http://localhost:8082> (loopback only, no sign-in). |
| `nginx` | `docker-compose.prod.yml` | Reverse proxy on ports `80`/`443` (config in `nginx/nginx.conf`). |
| `backup` | `docker-compose.prod.yml` | Runs `scripts/backup_db.py` once per day. |

All services share the `guardrails-network` bridge network.

## Usage

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your API keys and admin credentials

# 2a. Users reach the app directly on port 9000 (web + Redis + Redis Commander)
docker compose up -d

# 2b. Or the production stack: Nginx on port 80 in front of the app + daily backups
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d    # or: make prod

# 3. Check status / health (port 9000 answers on the Docker host in both cases)
docker compose ps
curl http://localhost:9000/health
```

A `Makefile` wraps common commands (`make dev`, `make prod`, `make stop`,
`make logs`, `make health`, `make backup`, `make test`, `make check-deploy`);
run `make help` to list targets.

## Behind Nginx: client addresses and the sign-in limit

`/login` allows 10 sign-in attempts per minute per client address, and the
"Admin signed in from" / "Failed sign-in from" log lines record that address.
Behind Nginx every request reaches the app from the Nginx container, so
`docker-compose.prod.yml` changes two things for the `web` service:

- `TRUSTED_PROXY_HOPS=1`: the app trusts exactly one proxy and takes the client
  address from the `X-Forwarded-For` entry Nginx appends. Without it every user
  shares one sign-in count, and a workshop locks itself out after ten attempts.
- The app port is published on `127.0.0.1` only. A client that could reach
  port 9000 directly could send its own `X-Forwarded-For` and pick the address
  the limit counts.

`nginx/nginx.conf` sets `X-Forwarded-For`, `X-Forwarded-Proto` and
`X-Forwarded-Host` (`$http_host`: the host and port the browser used) itself in
every location and removes `X-Forwarded-Port`, so a value a client sends is
never passed through. `make check-deploy` (and CI) checks all of this.

Notes:

- Needs Docker Compose 2.24.4 or later (the file uses `!override` to replace
  the public port). Check with
  `docker compose -f docker-compose.yml -f docker-compose.prod.yml config web`:
  one port with `host_ip: 127.0.0.1` and `TRUSTED_PROXY_HOPS: "1"`.
- Use both files for every command on that host (`make stop`, `make logs`,
  `make rebuild-prod` do), or put
  `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml` in `.env`. A plain
  `docker compose up -d` would otherwise recreate `web` with the direct-access
  settings while Nginx keeps running.
- Leave `TRUSTED_PROXY_HOPS=0` in `.env`. Raise it only for a proxy of your own
  that is the only way to reach the app port.
- `--profile production` is gone: the old command now starts only the base
  services. Stop an older production stack with
  `docker compose -f docker-compose.yml -f docker-compose.prod.yml down`.
- HTTPS: put `server.crt` and `server.key` in `nginx/ssl/` (ignored by git and
  by the Docker build), enable the TLS server block in `nginx/nginx.conf`, and
  set `SESSION_COOKIE_SECURE=true`.

## Rate Limiting with Redis

The `web` service is wired to Redis via
`RATE_LIMIT_STORAGE=redis://redis:6379/0`, which enables rate-limit state to be
shared across workers/instances. For a single container without Redis, set
`RATE_LIMIT_STORAGE=memory://` in `.env`.

## Backups

The `backup` service (`docker-compose.prod.yml`) runs `scripts/backup_db.py` on a
24-hour loop, writing timestamped copies of the SQLite database into `backups/`
and keeping the 10 most recent. You can also run it manually:

```bash
docker compose exec web python scripts/backup_db.py
```

## Notes

- The `web` container mounts the project directory and the `instance/`,
  `logs/`, `data/`, `backups/`, and `models_cache/` folders as volumes so data
  persists across restarts.
- LLM Guard models used for benchmarking are lazy-loaded on first use and cached
  under `models_cache/`.
