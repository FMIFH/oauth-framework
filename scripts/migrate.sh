#!/usr/bin/env bash
# Bash wrapper for database migrations script.
set -e

# Determine the directory of this script to refer to migrate.py relatively
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Check if we are running in docker or local environment with a virtual env
if [ -f "$ROOT_DIR/.venv/bin/python" ]; then
    PYTHON_EXEC="$ROOT_DIR/.venv/bin/python"
elif [ -f "$ROOT_DIR/venv/bin/python" ]; then
    PYTHON_EXEC="$ROOT_DIR/venv/bin/python"
else
    PYTHON_EXEC="python"
fi

# Execute migration script
exec "$PYTHON_EXEC" "$ROOT_DIR/migrate.py" "$@"
