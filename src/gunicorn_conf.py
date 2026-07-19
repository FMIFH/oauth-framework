"""
Gunicorn configuration file.
"""

import multiprocessing
import os

# Server socket
bind = os.getenv("GUNICORN_BIND", "0.0.0.0:8000")

# Worker processes
workers = int(
    os.getenv(
        "GUNICORN_WORKERS",
        multiprocessing.cpu_count() * 2 + 1,
    )
)

worker_class = os.getenv("GUNICORN_WORKER_CLASS", "sync")
threads = int(os.getenv("GUNICORN_THREADS", "1"))

# Timeouts
timeout = int(os.getenv("GUNICORN_TIMEOUT", "30"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")

# Process naming
proc_name = os.getenv("GUNICORN_PROC_NAME", "gunicorn")

# Restart workers after serving requests
max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", "1000"))
max_requests_jitter = int(os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "100"))

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Preload application for lower memory usage
preload_app = os.getenv("GUNICORN_PRELOAD", "false").lower() == "true"

# Temporary directory
worker_tmp_dir = "/dev/shm" if os.path.exists("/dev/shm") else None

# Daemon mode (usually False in containers)
daemon = False

# PID file (optional)
pidfile = os.getenv("GUNICORN_PIDFILE") or None

# Forwarded IPs
forwarded_allow_ips = "*"

# Enable statsd if configured
statsd_host = os.getenv("GUNICORN_STATSD_HOST") or None
