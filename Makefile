# Makefile for AI Guardrails Demo

.PHONY: help install dev prod test clean backup logs health

help: ## Show this help message
	@echo "AI Guardrails Demo - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip install -r requirements.txt

dev: ## Start development environment (simple)
	docker compose up -d

dev-prod: ## Start full production-ready environment
	docker compose -f docker-compose.production.yml up -d

prod: ## Start production environment with all services
	docker compose -f docker-compose.production.yml --profile production up -d

stop: ## Stop all services
	docker compose down
	docker compose -f docker-compose.production.yml down

restart: ## Restart all services
	docker compose -f docker-compose.production.yml restart

logs: ## View logs from all services
	docker compose -f docker-compose.production.yml logs -f

logs-web: ## View application logs only
	docker compose -f docker-compose.production.yml logs -f web

logs-redis: ## View Redis logs only
	docker compose -f docker-compose.production.yml logs -f redis

health: ## Check health of all services
	@echo "Checking application health..."
	@curl -f http://localhost:9000/health || echo "Application not reachable"
	@echo "\nChecking Redis health..."
	@docker compose -f docker-compose.production.yml exec redis redis-cli ping || echo "Redis not reachable"

backup: ## Create database backup
	docker compose -f docker-compose.production.yml exec web python scripts/backup_db.py

test: ## Run tests
	pytest tests/ -v

test-docker: ## Run tests in Docker environment
	docker compose -f docker-compose.production.yml up -d
	@sleep 5
	@curl -f http://localhost:9000/health
	docker compose -f docker-compose.production.yml down

clean: ## Clean up containers and volumes
	docker compose down -v
	docker compose -f docker-compose.production.yml down -v
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

clean-all: ## Clean up everything including backups
	$(MAKE) clean
	rm -rf backups/*
	rm -rf logs/*

rebuild: ## Rebuild and restart containers
	docker compose -f docker-compose.production.yml build --no-cache
	docker compose -f docker-compose.production.yml up -d

scale: ## Scale web service (use: make scale n=3)
	docker compose -f docker-compose.production.yml up -d --scale web=$(n)

redis-cli: ## Connect to Redis CLI
	docker compose -f docker-compose.production.yml exec redis redis-cli

redis-monitor: ## Monitor Redis commands
	docker compose -f docker-compose.production.yml exec redis redis-cli MONITOR

redis-flush: ## Flush all Redis data (WARNING: clears rate limits)
	docker compose -f docker-compose.production.yml exec redis redis-cli FLUSHALL

shell: ## Open shell in web container
	docker compose -f docker-compose.production.yml exec web /bin/bash

stats: ## Show container resource usage
	docker stats

pre-commit: ## Install pre-commit hooks
	pip install pre-commit
	pre-commit install

lint: ## Run linters
	flake8 app.py
	black --check app.py

format: ## Format code
	black app.py
