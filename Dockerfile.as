# Multi-stage build for minimized attack surface
FROM python:3.13-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

RUN pip install --no-cache-dir poetry

# Copy dependency definition files
COPY pyproject.toml poetry.lock ./

# Install runtime dependencies
RUN poetry install --only main --no-root && rm -rf $POETRY_CACHE_DIR

FROM python:3.13-slim AS runner

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtualenv and application code
COPY --from=builder /app/.venv /app/.venv
COPY src/ ./src
COPY alembic/ ./alembic
COPY alembic.ini .
COPY migrate.py .
COPY scripts/ ./scripts

ENV PATH=/app/.venv/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Run as non-privileged system user to prevent container escape
RUN useradd -m -u 10001 oauthuser
USER oauthuser

EXPOSE 8000
ENTRYPOINT ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-c", "src/gunicorn_conf.py", "src.main_as:app"]