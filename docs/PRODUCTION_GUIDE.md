# Full Environment Guide

This guide covers the multi-service deployment defined in the top-level
[`docker-compose.yml`](../docker-compose.yml). For a minimal
single-container / Gunicorn deployment and the production checklist, see
[PRODUCTION.md](PRODUCTION.md).

## Services

`docker-compose.yml` defines the following services:

| Service | Profile | Notes |
|---------|---------|-------|
| `web` | default | Main Flask application. Container entrypoint is `scripts/start_production.sh`. |
| `redis` | default | Redis 7 (appendonly) for distributed rate limiting. Host port `6380` → container `6379`. |
| `redis-commander` | default | Redis web UI at <http://localhost:8082>. |
| `nginx` | `production` | Reverse proxy on ports `80`/`443` (config in `nginx/nginx.conf`). |
| `backup` | `production` | Runs `scripts/backup_db.py` once per day. |

All services share the `lakera-network` bridge network.

## Usage

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your API keys and admin credentials

# 2. Start core services (web + Redis + Redis Commander)
docker compose up -d

# 3. Add the production profile (Nginx + automated backups)
docker compose --profile production up -d

# 4. Check status / health
docker compose ps
curl http://localhost:9000/health
```

A `Makefile` wraps common commands (`make dev`, `make prod`, `make logs`,
`make health`, `make backup`, `make test`); run `make help` to list targets.

## Rate Limiting with Redis

The `web` service is wired to Redis via
`RATE_LIMIT_STORAGE=redis://redis:6379/0`, which enables rate-limit state to be
shared across workers/instances. For a single container without Redis, set
`RATE_LIMIT_STORAGE=memory://` in `.env`.

## Backups

The `backup` service (production profile) runs `scripts/backup_db.py` on a
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
