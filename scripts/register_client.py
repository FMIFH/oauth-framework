#!/usr/bin/env python3
"""
OAuth Client Registration Helper Script.
Allows creating/registering OAuth clients and their secrets directly in the database.
"""

import argparse
import asyncio
import json
import os
import secrets
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.database import close_db, get_sessionmaker
from src.core.security import hash_password
from src.repositories.client_repo import ClientRepository


async def register_client(
    name: str,
    client_type: str,
    redirect_uris: list[str],
    grant_types: list[str],
    scopes: list[str],
    secret: str | None = None,
):
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as db:
        repo = ClientRepository(db)

        # Create Client
        client = await repo.create_client(
            client_name=name,
            client_type=client_type,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            scope=scopes,
        )

        plain_secret = None
        if client_type == "confidential":
            if not secret:
                plain_secret = secrets.token_urlsafe(32)
            else:
                plain_secret = secret

            # Hash and store client secret
            secret_hash = hash_password(plain_secret)
            await repo.create_client_secret(
                client_id=client.id,
                secret_hash=secret_hash,
            )

        print("[+] Client successfully registered!")
        print(f"    Client ID:     {client.id}")
        print(f"    Client Name:   {client.client_name}")
        print(f"    Client Type:   {client.client_type}")
        print(f"    Redirect URIs: {json.loads(client.redirect_uris)}")
        print(f"    Grant Types:   {client.grant_types}")
        print(f"    Scopes:        {client.scope}")

        if plain_secret:
            print(f"    Client Secret: {plain_secret}")
            print("    * WARNING: Keep this secret safe! It is stored as a hash and cannot be recovered.")
        else:
            print("    Client Secret: None (Public Client)")


def main():
    parser = argparse.ArgumentParser(description="Register a new OAuth Client.")
    parser.add_argument(
        "--name",
        type=str,
        default="Test Client",
        help="The name of the client (default: 'Test Client')",
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["confidential", "public"],
        default="confidential",
        help="Client type: 'confidential' or 'public' (default: 'confidential')",
    )
    parser.add_argument(
        "--redirect-uris",
        type=str,
        default="http://localhost:8080/callback,https://oauth.pstmn.io/v1/callback",
        help="Comma-separated redirect URIs",
    )
    parser.add_argument(
        "--grant-types",
        type=str,
        default="authorization_code,refresh_token",
        help="Comma-separated grant types",
    )
    parser.add_argument(
        "--scopes",
        type=str,
        default="openid,profile,email",
        help="Comma-separated scopes",
    )
    parser.add_argument(
        "--secret",
        type=str,
        default=None,
        help="Specify custom client secret (confidential clients only)",
    )

    args = parser.parse_args()

    # Parse comma-separated strings into lists
    redirect_uris_list = [uri.strip() for uri in args.redirect_uris.split(",") if uri.strip()]
    grant_types_list = [gt.strip() for gt in args.grant_types.split(",") if gt.strip()]
    scopes_list = [sc.strip() for sc in args.scopes.split(",") if sc.strip()]

    async def run():
        try:
            await register_client(
                name=args.name,
                client_type=args.type,
                redirect_uris=redirect_uris_list,
                grant_types=grant_types_list,
                scopes=scopes_list,
                secret=args.secret,
            )
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            await close_db()

    asyncio.run(run())


if __name__ == "__main__":
    main()
