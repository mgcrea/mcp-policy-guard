.PHONY: help install format lint spec build

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install dependencies with uv
	uv sync

format: ## Format code
	uv run ruff check --fix; uv run ruff format

lint: ## Lint code
	uv run ruff check

spec: ## Run tests
	uv run pytest -s

build: ## Build the wheel and sdist
	uv build
