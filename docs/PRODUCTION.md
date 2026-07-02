# Production Deployment Guide

## Quick Start

### Using Docker Compose (Recommended)

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 2. Start the application
docker compose up -d

# 3. Check health
curl http://localhost:9000/health
```

### Using Gunicorn Directly

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:9000 --timeout 120 app:app
```

## Production Checklist

- [ ] Configure all environment variables in `.env`
- [ ] Set `APP_PORT` if not using default 9000
- [ ] Configure API keys for Lakera Guard
- [ ] (Optional) Configure LLM providers
- [ ] Set up regular database backups
- [ ] Configure reverse proxy (nginx/Apache)
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

### Automated Backups

Add to crontab for daily backups:
```cron
0 2 * * * cd /path/to/lakera-demo && python scripts/backup_db.py
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
- **Default**: 200 requests per day, 50 per hour per IP
- **Storage**: In-memory (resets on restart)

For production, consider using Redis for persistent rate limiting.

## CORS Configuration

CORS is enabled for API endpoints with the following settings:
- **Allowed Origins**: `*` (all origins)
- **Endpoints**: `/api/*`

For production, restrict origins to your specific domains.

## Performance Tuning

### Gunicorn Workers

The default configuration uses 4 workers. Adjust based on your server:

```bash
# General formula: (2 x CPU cores) + 1
gunicorn -w <number_of_workers> -b 0.0.0.0:9000 app:app
```

### Timeout

Default timeout is 120 seconds for LLM API calls. Adjust if needed:

```bash
gunicorn -w 4 -b 0.0.0.0:9000 --timeout 180 app:app
```

## Reverse Proxy Configuration

### Nginx Example

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Apache Example

```apache
<VirtualHost *:80>
    ServerName your-domain.com
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:9000/
    ProxyPassReverse / http://localhost:9000/
</VirtualHost>
```

## Security Recommendations

1. **Never commit `.env` file** - Already in `.gitignore`
2. **Use environment-specific configurations** - Separate `.env` for dev/staging/prod
3. **Enable HTTPS** - Use Let's Encrypt for free SSL certificates
4. **Restrict CORS** - Limit to your specific domains in production
5. **API Rate Limiting** - Monitor and adjust limits based on usage
6. **Regular Updates** - Keep dependencies up to date
7. **Database Backups** - Automate daily backups
8. **Monitoring** - Set up alerts for health check failures

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
ls -lh instance/lakera_logs.db

# Restore from backup
cp backups/lakera_logs_backup_YYYYMMDD_HHMMSS.db instance/lakera_logs.db
```

### High Memory Usage

```bash
# Reduce Gunicorn workers
gunicorn -w 2 -b 0.0.0.0:9000 app:app

# Or limit memory in docker-compose.yml
services:
  web:
    deploy:
      resources:
        limits:
          memory: 512M
```
