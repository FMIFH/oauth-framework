#!/usr/bin/env python3
"""
Key Rotation Background Worker Daemon.
This worker runs continuously, performing the signing key rotation check
immediately upon start, and then once every 24 hours (daily).
"""

import asyncio
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import settings
from src.core.database import close_db, get_sessionmaker
from src.core.redis import close_redis
from src.repositories.authorization_code_repo import AuthorizationCodeRepository
from src.services.key_manager import rotate_keys


async def check_and_rotate():
    """Execute the key rotation routine."""
    print("[*] Worker triggering key rotation check...")
    sessionmaker = get_sessionmaker()
    try:
        async with sessionmaker() as db:
            rotated = await rotate_keys(db=db, master_key_hex=settings.master_encryption_key)
            if rotated:
                print(f"[+] Worker successfully rotated {len(rotated)} key(s):")
                for key in rotated:
                    print(f"    - Algorithm: {key.algorithm}, Kid: {key.kid}")
            else:
                print("[+] Worker checked keys: no rotation required today.")

            # 2. Clean up expired authorization codes
            auth_code_repo = AuthorizationCodeRepository(db)
            await auth_code_repo.delete_expired_codes()
            print("[+] Worker successfully pruned expired authorization codes.")
    except Exception as e:
        print(f"[-] Worker encountered error during rotation check: {e}", file=sys.stderr)


async def main():
    print("[*] Starting Key Rotation Background Worker (daily interval)...")
    # Run once immediately on start
    await check_and_rotate()

    # Repeat daily
    daily_interval = 24 * 60 * 60  # 24 hours
    while True:
        print("[*] Worker sleeping for 24 hours...")
        try:
            await asyncio.sleep(daily_interval)
            await check_and_rotate()
        except asyncio.CancelledError:
            print("[*] Worker received cancellation request. Shutting down...")
            break
        except Exception as e:
            print(f"[-] Worker loop error: {e}", file=sys.stderr)
            # Short sleep to prevent fast infinite crash loops in case of persistent errors
            await asyncio.sleep(60)

    # Clean up connections
    await close_db()
    await close_redis()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[*] Worker stopped by user.")
