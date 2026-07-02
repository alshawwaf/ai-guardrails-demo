# Configuration Reference

## Environment Variables

All application settings can be configured via environment variables in the `.env` file.

### Lakera Guard Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LAKERA_API_KEY` | Lakera Guard API authentication key | - | Yes |
| `LAKERA_PROJECT_ID` | Lakera project identifier | - | Yes |
| `LAKERA_API_URL` | Lakera API endpoint | `https://api.lakera.ai/v2/guard` | No |

### LLM Provider Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key | - | No |
| `OPENAI_API_URL` | OpenAI API endpoint | `https://api.openai.com/v1/chat/completions` | No |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | - | No |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | - | No |
| `AZURE_OPENAI_DEPLOYMENT` | Azure deployment name | `gpt-4o-mini-2024-07-18` | No |
| `GEMINI_API_KEY` | Google Gemini API key | - | No |

### Application Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `APP_PORT` | Application port number | `9000` | No |
| `LOGS_DIR` | Log file directory | `logs` | No |
| `LOG_FILENAME` | Log file name | `application.log` | No |

### CORS Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CORS_ORIGINS` | Allowed origins for API calls | `*` | No |

**Examples:**
- Allow all: `CORS_ORIGINS=*`
- Single domain: `CORS_ORIGINS=https://example.com`
- Multiple domains: `CORS_ORIGINS=https://example.com,https://app.example.com`

### Rate Limiting Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RATE_LIMIT_DAILY` | Maximum requests per day per IP | `200` | No |
| `RATE_LIMIT_HOURLY` | Maximum requests per hour per IP | `50` | No |
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
| `GUNICORN_WORKERS` | Number of worker processes | `4` | No |
| `GUNICORN_TIMEOUT` | Request timeout in seconds | `120` | No |
| `GUNICORN_BIND` | Bind address and port | `0.0.0.0:9000` | No |

**Worker Calculation:**
```bash
# Recommended formula: (2 × CPU cores) + 1
# For 2 CPU cores: (2 × 2) + 1 = 5 workers
GUNICORN_WORKERS=5
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
CORS_ORIGINS=*
RATE_LIMIT_DAILY=1000
RATE_LIMIT_HOURLY=200
RATE_LIMIT_STORAGE=memory://
GUNICORN_WORKERS=2
```

### Staging Environment

```env
# .env.staging
APP_PORT=9000
CORS_ORIGINS=https://staging.example.com
RATE_LIMIT_DAILY=500
RATE_LIMIT_HOURLY=100
RATE_LIMIT_STORAGE=redis://redis:6379/0
GUNICORN_WORKERS=4
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
GUNICORN_WORKERS=8
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
      - GUNICORN_WORKERS=4
      - RATE_LIMIT_STORAGE=memory://
```

### Multi-Instance with Redis

```yaml
# docker compose.yml
services:
  web:
    environment:
      - GUNICORN_WORKERS=4
      - RATE_LIMIT_STORAGE=redis://redis:6379/0
    replicas: 3
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
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
# More workers for CPU-bound workloads
GUNICORN_WORKERS=8 docker compose up

# Longer timeout for slow APIs
GUNICORN_TIMEOUT=300 docker compose up
```

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
