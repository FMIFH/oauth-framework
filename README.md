# OAuth 2.1 Authorization Framework

This repository contains a modern, enterprise-grade, and production-ready implementation of the **OAuth 2.1 Authorization Framework**.

OAuth 2.1 consolidates and security-hardens the core OAuth 2.0 specifications by systematically deprecating insecure patterns (such as the Implicit and Resource Owner Password Credentials grants) while making the Proof Key for Code Exchange (PKCE) flow mandatory for public clients.

---

## 🚀 Key Features

- **Strict OAuth 2.1 Compliance**: Fully adheres to modern security practices, deprecating insecure flows and enforcing mandatory PKCE.
- **Asynchronous FastAPI Engine**: Engineered with Python 3.13 and FastAPI for high-performance, asynchronous routing and native type safety.
- **Segregated Actor Architecture**: Strict logical and physical separation between the **Authorization Server (AS)**, **Resource Server (RS)**, and **Client Application** to limit attack surfaces.
- **Secure Client Registration**: CLI utility for registering confidential or public OAuth clients and storing cryptographically hashed secrets. *(Note: Dynamic Client Registration (DCR) via API is currently a work in progress).*
- **Asymmetric Key Lifecycle**: Built-in cryptographic key management supporting RSA/EC key generation, secure rotation, and JSON Web Key Sets (JWKS) distribution.
- **Distributed Caching & Session Management**: Built on Redis for low-latency storage of ephemeral authorization codes, PKCE verifiers, rate-limiting counters, and token revocation lists.
- **Relational Relational Database Schema**: PostgreSQL 16 backing core tables (users, clients, keys, and tokens) with asynchronous SQLAlchemy 2.0 ORM patterns and Alembic migration tracking.

---

## 🛠️ Technology Stack

- **Web Framework:** FastAPI (v0.111.0+)
- **Database Engine:** PostgreSQL (v16+) & Redis (v7.2+)
- **ORM & Migrations:** SQLAlchemy (v2.0+) & Alembic (v1.13.0+)
- **Protocol & Cryptography:** Authlib (v1.3.0+) & Argon2 (argon2-cffi)
- **Runtime:** Python 3.13+

---

## 🏃 Getting Started

### Prerequisites

Ensure you have the following installed locally:
- [Docker & Docker Compose](https://www.docker.com/)
- [Python 3.13+](https://www.python.org/)
- [Poetry](https://python-poetry.org/)

---

### 🐳 Quick Start with Docker

The fastest way to spin up the entire environment (PostgreSQL, Redis, Authorization Server, Migrations, and Key Rotation Workers) is using Docker Compose:

```bash
docker compose up --build
```

The Authorization Server will start and listen at `http://localhost:8000`. You can verify its health at:
- Root: `http://localhost:8000/`
- Health check: `http://localhost:8000/health`
- OpenAPI Swagger Documentation: `http://localhost:8000/docs`

---

### 🐍 Local Development Setup

To run and develop the application directly on your host machine:

1. **Install Dependencies**:
   ```bash
   make install
   ```

2. **Configure Environment**:
   Ensure PostgreSQL and Redis are running, then set up your local environment variables or configuration file mapping to your local instances.

3. **Run Migrations**:
   Run the Alembic database migrations:
   ```bash
   poetry run python migrate.py upgrade head
   ```

4. **Start the Application**:
   You can start the FastAPI application using Uvicorn or Gunicorn:
   ```bash
   poetry run uvicorn src.main_as:app --reload --port 8000
   ```

---

## 📝 Registering an OAuth Client

A secure CLI command is available to register confidential or public clients into the database.

*(Note: Dynamic Client Registration (DCR) via standard OAuth 2.1 API endpoints is currently a work in progress; clients should be registered using this CLI tool for now).*

### Confidential Client (Auto-generated secret)
```bash
poetry run python scripts/register_client.py --name "Test Client" --type confidential
```

### Public Client (No secret / PKCE mandatory)
```bash
poetry run python scripts/register_client.py --name "Public SPA" --type public
```

### Custom Client Setup
```bash
poetry run python scripts/register_client.py \
  --name "My Custom Client" \
  --type confidential \
  --redirect-uris "http://localhost:3000/callback" \
  --grant-types "authorization_code" \
  --scopes "openid,profile" \
  --secret "my-custom-super-secure-secret-123"
```

---

## 🛡️ Quality Assurance & Testing

This project includes a fully-configured QA and test pipeline. You can run all quality gates with single commands:

- **Run all QA gates** (Formatter, Linter, Type Checker, and Tests):
  ```bash
  make qa
  ```
- **Run the test suite**:
  ```bash
  make test
  ```
- **Run only Unit Tests**:
  ```bash
  make test-unit
  ```
- **Run only Integration Tests**:
  ```bash
  make test-integration
  ```
- **View Test Coverage**:
  ```bash
  make test-cov
  ```
- **Format Code**:
  ```bash
  make format
  ```
- **Lint Code**:
  ```bash
  make lint
  ```
