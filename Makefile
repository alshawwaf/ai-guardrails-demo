# Makefile for AI Guardrails Demo (+ AI Guard Demo Kit / Gateway Mode)
#
# The compose stack is docker-compose.yml (web + Redis + Redis Commander).
# docker-compose.prod.yml adds Nginx + backup and puts the app behind nginx
# (TRUSTED_PROXY_HOPS=1, app port on loopback only). docker-compose-dev.yml
# builds the image locally and runs gunicorn with live reload.

COMPOSE ?= docker compose
PROD_COMPOSE ?= $(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml
DEV_COMPOSE ?= $(COMPOSE) -f docker-compose-dev.yml
PYTHON ?= python3
APP_PORT ?= 9000
# Extra arguments for aiguard-run, e.g. make aiguard-run ARGS="preflight --server 10.1.1.101 --api-key-env AIGUARD_MGMT_KEY"
ARGS ?=

.PHONY: help install dev dev-prod dev-local prod stop restart logs logs-web logs-redis health \
        backup test test-docker check-deploy clean clean-all rebuild rebuild-prod scale redis-cli \
        redis-monitor redis-flush shell stats pre-commit lint format \
        aiguard-test aiguard-help aiguard-version aiguard-status aiguard-logs aiguard-run

help: ## Show this help message
	@echo "AI Guardrails Demo - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip install -r requirements.txt

dev: ## Start web + Redis + Redis Commander (docker-compose.yml)
	$(COMPOSE) up -d

dev-prod: ## Same stack as dev (docker-compose.yml, without nginx)
	$(COMPOSE) up -d

dev-local: ## Build the image here and run it with gunicorn --reload (docker-compose-dev.yml)
	$(DEV_COMPOSE) up -d --build

prod: ## Start everything incl. Nginx (port 80) + backup (docker-compose.prod.yml)
	$(PROD_COMPOSE) up -d

stop: ## Stop all services (all compose files)
	$(PROD_COMPOSE) down
	$(DEV_COMPOSE) down

restart: ## Restart all services
	$(PROD_COMPOSE) restart

logs: ## View logs from all services
	$(PROD_COMPOSE) logs -f

logs-web: ## View application logs only
	$(COMPOSE) logs -f web

logs-redis: ## View Redis logs only
	$(COMPOSE) logs -f redis

health: ## Check health of all services
	@echo "Checking application health..."
	@curl -f http://localhost:$(APP_PORT)/health || echo "Application not reachable"
	@echo "\nChecking Redis health..."
	@$(COMPOSE) exec redis redis-cli ping || echo "Redis not reachable"

backup: ## Create database backup
	$(COMPOSE) exec web python scripts/backup_db.py

test: ## Run all tests (the app tests need requirements.txt installed)
	$(PYTHON) -m pytest tests/ -v

test-docker: ## Start the stack, check /health, stop it
	$(COMPOSE) up -d
	@sleep 5
	@curl -f http://localhost:$(APP_PORT)/health
	$(COMPOSE) down

check-deploy: ## Check the nginx/compose proxy and port settings (what CI checks)
	$(PYTHON) scripts/check_deploy_config.py --self-test

clean: ## Clean up containers and volumes
	$(PROD_COMPOSE) down -v
	$(DEV_COMPOSE) down -v
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

clean-all: ## Clean up everything including backups
	$(MAKE) clean
	rm -rf backups/*
	rm -rf logs/*

rebuild: ## Pull the latest images and recreate the web + Redis stack
	$(COMPOSE) pull
	$(COMPOSE) up -d --force-recreate

rebuild-prod: ## Pull the latest images and recreate the production stack (with Nginx)
	$(PROD_COMPOSE) pull
	$(PROD_COMPOSE) up -d --force-recreate

scale: ## Scale web (make scale n=3). Not with Gateway Mode: it needs ONE app process
	$(COMPOSE) up -d --scale web=$(n)

redis-cli: ## Connect to Redis CLI
	$(COMPOSE) exec redis redis-cli

redis-monitor: ## Monitor Redis commands
	$(COMPOSE) exec redis redis-cli MONITOR

redis-flush: ## Flush all Redis data (WARNING: clears rate limits)
	$(COMPOSE) exec redis redis-cli FLUSHALL

shell: ## Open shell in web container
	$(COMPOSE) exec web /bin/bash

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

# --------------------------------------------------------------------------
# AI Guard Demo Kit (aiguard/, stdlib only). See docs/GATEWAY_MODE.md.
# --------------------------------------------------------------------------

aiguard-test: ## Run the aiguard core tests (needs only pytest + cryptography)
	$(PYTHON) -m pytest tests/core -q

aiguard-help: ## Show the aiguard commands
	$(PYTHON) -m aiguard --help

aiguard-version: ## Show the aiguard version
	$(PYTHON) -m aiguard version

aiguard-status: ## Show the last server, rollback points, latest log and report
	$(PYTHON) -m aiguard status

aiguard-logs: ## Show warnings, errors and hints from the latest aiguard run log
	$(PYTHON) -m aiguard logs --errors

aiguard-run: ## Run any aiguard command: make aiguard-run ARGS="preflight --server X --api-key-env VAR"
	$(PYTHON) -m aiguard $(ARGS)
