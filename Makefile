# TrustProof-Cloud - developer entry points.
# Every target below runs locally, offline, and free of charge.

PY ?= python3
PORT ?= 8000

.PHONY: help install install-optional test test-cov lint fmt demo experiment api clean reset docker-build docker-up docker-down

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:              ## Install core dependencies
	$(PY) -m pip install -r requirements.txt

install-optional:     ## Install optional extras (Redis, Streamlit, charts, ...)
	$(PY) -m pip install -r requirements-optional.txt

test:                 ## Run the full test suite
	$(PY) -m pytest tests/ -q

test-cov:             ## Run tests with a coverage report
	$(PY) -m pytest tests/ --cov=crypto --cov=services --cov=ml --cov-report=term-missing

lint:                 ## Static analysis
	$(PY) -m ruff check .

fmt:                  ## Auto-format
	$(PY) -m ruff format .

demo:                 ## End-to-end walkthrough of one verified inference
	$(PY) scripts/demo.py

experiment:           ## Run the minimum viable experiment (6 arms x 3 seeds)
	$(PY) -m experiments.runners.mve --tasks 150 --seeds 3

api:                  ## Start the API gateway on $(PORT)
	$(PY) -m uvicorn services.api.main:app --host 0.0.0.0 --port $(PORT)

reset:                ## Delete experiment data, database and cached models (keeps results)
	rm -rf data/trustproof.db data/models data/keys
	@echo "local state reset; experiments/results left intact"

clean: reset          ## reset + remove caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov

docker-build:         ## Build the container image
	docker build -t trustproof-cloud:0.2.0 .

docker-up:            ## Start the local stack
	docker compose up --build

docker-down:          ## Stop the local stack and remove volumes
	docker compose down -v
