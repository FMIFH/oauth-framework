#!/usr/bin/env python3
"""
Alembic Database Migration Helper Script.
Provides options to wait for the database, run migrations, auto-generate revisions,
show history, and downgrade revisions.
"""

import argparse
import asyncio
import os
import sys

from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command

# Ensure root folder is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from src.config import settings

# Load Alembic configuration
ALEMBIC_INI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alembic.ini")
alembic_cfg = Config(ALEMBIC_INI_PATH)


async def check_db_connection(dsn: str) -> bool:
    """Attempt to connect to the database to check if it's responsive."""
    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as conn:
            # We must await the execution for async connections in sqlalchemy 2.0

            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return True
    except (DBAPIError, Exception) as e:
        print(f"DEBUG: Connection error detail: {e}")
        await engine.dispose()
        return False


async def wait_for_db(dsn: str, timeout: int = 60, interval: int = 2) -> bool:
    """Wait for the database to become ready within a specific timeout."""
    print(f"[*] Checking database connection to {dsn.split('@')[-1]}...")
    start_time = asyncio.get_event_loop().time()

    while True:
        if await check_db_connection(dsn):
            print("[+] Database is ready!")
            return True

        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed >= timeout:
            print(f"[-] Database connection timeout reached ({timeout}s).")
            return False

        print(f"[-] Database not ready yet, retrying in {interval}s... ({int(timeout - elapsed)}s remaining)")
        await asyncio.sleep(interval)


def run_upgrade(revision: str = "head") -> None:
    """Apply migrations up to the specified revision."""
    print(f"[*] Running database upgrade to '{revision}'...")
    try:
        command.upgrade(alembic_cfg, revision)
        print("[+] Migration upgrade completed successfully.")
    except Exception as e:
        print(f"[-] Error running migration upgrade: {e}", file=sys.stderr)
        sys.exit(1)


def run_downgrade(revision: str = "-1") -> None:
    """Revert migrations down to the specified revision."""
    print(f"[*] Running database downgrade to '{revision}'...")
    try:
        command.downgrade(alembic_cfg, revision)
        print("[+] Migration downgrade completed successfully.")
    except Exception as e:
        print(f"[-] Error running migration downgrade: {e}", file=sys.stderr)
        sys.exit(1)


def run_revision(message: str, autogenerate: bool = True) -> None:
    """Generate a new migration script."""
    print(f"[*] Creating a new migration revision with message: '{message}'...")
    try:
        command.revision(alembic_cfg, message=message, autogenerate=autogenerate)
        print("[+] Migration revision created successfully.")
    except Exception as e:
        print(f"[-] Error creating migration revision: {e}", file=sys.stderr)
        sys.exit(1)


def run_history() -> None:
    """Show database migration history."""
    print("[*] Migration History:")
    try:
        command.history(alembic_cfg)
    except Exception as e:
        print(f"[-] Error showing migration history: {e}", file=sys.stderr)
        sys.exit(1)


def run_current() -> None:
    """Show the current migration revision."""
    print("[*] Current Migration Revision:")
    try:
        command.current(alembic_cfg)
    except Exception as e:
        print(f"[-] Error showing current migration: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    # Parent parser for shared arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--skip-wait", action="store_true", help="Skip waiting for database readiness")
    parent_parser.add_argument("--timeout", type=int, default=60, help="Max wait timeout in seconds")
    parent_parser.add_argument("--interval", type=int, default=2, help="Retry interval in seconds")

    parser = argparse.ArgumentParser(description="Alembic database migrations manager for OAuth Framework.")

    subparsers = parser.add_subparsers(dest="command", help="Migration command to run")

    # Wait command
    subparsers.add_parser("wait", parents=[parent_parser], help="Wait for database to be ready")

    # Upgrade command
    parser_upgrade = subparsers.add_parser(
        "upgrade", parents=[parent_parser], help="Run database migrations to latest/head"
    )
    parser_upgrade.add_argument("revision", nargs="?", default="head", help="Revision target (default: head)")

    # Downgrade command
    parser_downgrade = subparsers.add_parser(
        "downgrade", parents=[parent_parser], help="Revert database migrations"
    )
    parser_downgrade.add_argument(
        "revision", nargs="?", default="-1", help="Revision target or offset, e.g. -1 (default: -1)"
    )

    # Revision command
    parser_revision = subparsers.add_parser(
        "revision", parents=[parent_parser], help="Generate a new migration revision"
    )
    parser_revision.add_argument("-m", "--message", required=True, help="Migration description message")
    parser_revision.add_argument(
        "--no-autogenerate", action="store_true", help="Disable autogenerate (create blank template)"
    )

    # History command
    subparsers.add_parser("history", parents=[parent_parser], help="Show migration history list")

    # Current command
    subparsers.add_parser("current", parents=[parent_parser], help="Show current revision information")

    # Default is upgrade
    args = parser.parse_args()
    cmd = args.command or "upgrade"

    # If no command specified, default upgrade target is head
    target_revision = getattr(args, "revision", "head")
    skip_wait = getattr(args, "skip_wait", False)

    # Commands requiring DB access and waiting
    db_dependent_commands = ["wait", "upgrade", "downgrade", "revision", "current"]

    if cmd in db_dependent_commands and not skip_wait:
        # Determine wait settings
        timeout = getattr(args, "timeout", 60)
        interval = getattr(args, "interval", 2)

        # Run async wait in a closed-loop event loop
        db_ready = asyncio.run(wait_for_db(settings.postgres_dsn, timeout, interval))
        if not db_ready:
            print("[-] Exiting due to database connection failure.", file=sys.stderr)
            sys.exit(1)

    if cmd == "wait":
        # We already waited successfully
        return
    elif cmd == "upgrade":
        run_upgrade(target_revision)
    elif cmd == "downgrade":
        run_downgrade(target_revision)
    elif cmd == "revision":
        run_revision(args.message, not args.no_autogenerate)
    elif cmd == "history":
        run_history()
    elif cmd == "current":
        run_current()


if __name__ == "__main__":
    main()
