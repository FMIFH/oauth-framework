# Makefile for oauth-framework
# Handles Quality Assurance (QA), cleaning, and linting tasks

# Configuration
SRC_DIR = src
TEST_DIR = tests
POETRY_RUN = poetry run

# Executables
PYTHON   = $(POETRY_RUN) python
PYTEST   = $(POETRY_RUN) pytest
RUFF     = $(POETRY_RUN) ruff
MYPY     = $(POETRY_RUN) mypy

.PHONY: help
help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install all dependencies including development ones
	poetry install

.PHONY: lint
lint: ## Run linting checks on the codebase (ruff check)
	$(RUFF) check $(SRC_DIR) $(TEST_DIR)

.PHONY: lint-fix
lint-fix: ## Automatically fix linting errors and sort imports (ruff check --fix)
	$(RUFF) check --fix $(SRC_DIR) $(TEST_DIR)

.PHONY: format
format: ## Format the codebase using ruff format
	$(RUFF) format $(SRC_DIR) $(TEST_DIR)

.PHONY: format-check
format-check: ## Check code formatting without applying changes
	$(RUFF) format --check $(SRC_DIR) $(TEST_DIR)

.PHONY: type-check
type-check: ## Run static type checking using mypy
	$(MYPY) --explicit-package-bases $(SRC_DIR)

.PHONY: test
test: ## Run the entire test suite
	$(PYTEST)

.PHONY: test-unit
test-unit: ## Run only unit tests
	$(PYTEST) $(TEST_DIR)/unit

.PHONY: test-integration
test-integration: ## Run only integration tests
	$(PYTEST) $(TEST_DIR)/integration

.PHONY: test-cov
test-cov: ## Run tests and output a coverage report
	$(PYTEST) --cov=$(SRC_DIR) --cov-report=term-missing --cov-report=html

.PHONY: clean
clean: ## Clean cache files, temporary files, and coverage outputs
	@echo "Cleaning temporary and cache files..."
	@$(PYTHON) -c "import shutil, glob, os; \
	[shutil.rmtree(p, ignore_errors=True) for p in ['.pytest_cache', '.mypy_cache', '.ruff_cache', 'htmlcov', 'dist', 'build'] + glob.glob('**/__pycache__', recursive=True) + glob.glob('*.egg-info')]; \
	[os.remove(f) for f in ['.coverage'] + glob.glob('**/*.py[cod]', recursive=True) if os.path.exists(f)]"
	@echo "Clean completed."

.PHONY: qa
qa: format-check lint type-check ## Run full QA pipeline (format check, lint, type check, tests with 100% coverage)
	$(PYTEST) --cov=$(SRC_DIR) --cov-report=term-missing --cov-fail-under=100
	@echo "QA pipeline passed successfully!"
