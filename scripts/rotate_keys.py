#!/usr/bin/env python3
"""
Key Rotation CLI script.
This script is intended to be executed on a schedule (e.g., cron job,
Kubernetes CronJob, or task scheduler) in a single-instance worker container
to avoid multiple web app instances rotating keys simultaneously.
"""

import asyncio
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import settings
from src.core.database import close_db, get_sessionmaker
from src.core.redis import close_redis
from src.services.key_manager import rotate_keys


async def main():
    print("[*] Starting key rotation check...")
    sessionmaker = get_sessionmaker()

    try:
        async with sessionmaker() as db:
            rotated = await rotate_keys(
                db=db,
                master_key_hex=settings.master_encryption_key
            )
            if rotated:
                print(f"[+] Successfully rotated {len(rotated)} key(s):")
                for key in rotated:
                    print(f"    - Algorithm: {key.algorithm}, Kid: {key.kid}")
            else:
                print("[+] No keys required rotation at this time.")
    except Exception as e:
        print(f"[-] Error during key rotation execution: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Clean up database and redis connections
        await close_db()
        await close_redis()


if __name__ == "__main__":
    asyncio.run(main())
