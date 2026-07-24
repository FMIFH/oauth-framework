import base64
import hashlib
import json
import secrets
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from redis.asyncio import Redis

from src.config import settings
from src.core.redis import get_redis
from src.core.security import verify_password
from src.exceptions.invalid_scope_exception import InvalidScopeError
from src.models.client import Client
from src.repositories.authorization_code_repo import AuthorizationCodeRepository, get_authorization_code_repo
from src.repositories.client_repo import ClientRepository, get_client_repository
from src.services.key_service import KeyService
from src.services.token_service import TokenService


class OAuthService:
    def __init__(
        self,
        client_repo: ClientRepository,
        authorization_code_repo: AuthorizationCodeRepository,
        background_tasks: BackgroundTasks,
        redis_pool: Redis,
    ):
        self.client_repo = client_repo
        self.authorization_code_repo = authorization_code_repo
        self.background_tasks = background_tasks
        self.redis_pool = redis_pool

    async def get_and_validate_client(self, client_id: str, redirect_uri: str) -> Client:
        """Validate the client ID and redirect URI."""
        try:
            client_uuid = uuid.UUID(client_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid client ID format",
            )

        client = await self.client_repo.get_by_id(client_uuid)
        if not client:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client not found",
            )

        try:
            allowed_redirect_uris = json.loads(client.redirect_uris)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Client configuration error (redirect_uris)",
            )

        if redirect_uri not in allowed_redirect_uris:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid redirect URI",
            )

        return client

    async def authenticate_client(self, client_id: str, client_secret: str | None = None) -> Client:
        """Authenticate a client based on its client_id and optional client_secret."""
        try:
            client_uuid = uuid.UUID(client_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client ID format",
            )

        client = await self.client_repo.get_by_id(client_uuid)
        if not client:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client not found",
            )

        if client.client_type == "confidential":
            if not client_secret:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Client secret is required for confidential clients",
                )
            active_secrets = await self.client_repo.get_active_secrets(client.id)

            is_valid = False
            for secret in active_secrets:
                if verify_password(client_secret, secret.secret_hash):
                    is_valid = True
                    break
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid client credentials",
                )
        return client

    def validate_scope(self, requested_scope: str, client: Client) -> None:
        """Validate the requested scope against the client's allowed scopes."""
        if not requested_scope:
            return
        allowed_scopes = set(client.scope.split())
        requested_scopes = set(requested_scope.split())
        if not requested_scopes.issubset(allowed_scopes):
            raise InvalidScopeError("Requested scope is not allowed for this client.")

    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> str:
        """Generate an authorization code and persist it in Database and Redis."""
        auth_code = secrets.token_urlsafe(32)
        payload = {
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        # Always persist in DB first
        await self.authorization_code_repo.create(
            code=auth_code,
            client_id=client_id,
            user_id=user_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            redirect_uri=redirect_uri,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.auth_code_ttl),
        )
        # Try to cache in Redis, but gracefully log if Redis is down
        try:
            key = f"auth:code:{auth_code}"
            await self.redis_pool.setex(
                key,
                settings.auth_code_ttl,
                json.dumps(payload),
            )
        except Exception:
            pass
        return auth_code

    async def consume_authorization_code(self, code: str) -> dict | None:
        """Retrieve and delete the authorization code from Redis or Database (one-time use)."""
        key = f"auth:code:{code}"
        try:
            data = await self.redis_pool.getdel(key)
            redis_healthy = True
        except Exception:
            data = None
            redis_healthy = False

        if redis_healthy:
            if data:
                # Code found in Redis. Deletion from DB can be done asynchronously!
                # Because Redis is healthy, any replay attack of this code will hit Redis,
                # return a miss, and not check the DB. So async deletion is 100% safe.
                self.background_tasks.add_task(self.authorization_code_repo.consume_code, code)
                return json.loads(data)

        # Redis is down or code not found in Redis. Fall back to the database synchronously.
        auth_code = await self.authorization_code_repo.consume_code(code)
        if auth_code:
            return {
                "client_id": str(auth_code.client_id),
                "user_id": str(auth_code.user_id),
                "redirect_uri": auth_code.redirect_uri,
                "scope": auth_code.scope,
                "code_challenge": auth_code.code_challenge,
                "code_challenge_method": auth_code.code_challenge_method,
            }
        return None

    async def process_authorization_request(
        self,
        user_id: str | None,
        response_type: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> RedirectResponse:
        """Process authorize request: validate client, scope, and check user authentication."""
        if response_type != "code":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="unsupported_response_type",
            )

        client = await self.get_and_validate_client(client_id, redirect_uri)

        # Validate the requested scope
        try:
            self.validate_scope(scope, client)
        except InvalidScopeError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )

        # 2. Check if user is authenticated via cookie
        if not user_id:
            # Redirect user to the login page, passing all OAuth parameters
            params = {
                "response_type": response_type,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            }
            query_string = urllib.parse.urlencode(params)
            return RedirectResponse(
                url=f"/users/login?{query_string}",
                status_code=status.HTTP_303_SEE_OTHER,
            )

        # 3. Create authorization code
        code = await self.create_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        # 4. Redirect user back to the client redirect_uri with code and state
        redirect_params = {
            "code": code,
            "state": state,
        }
        parsed_url = urllib.parse.urlparse(redirect_uri)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for k, v in redirect_params.items():
            query_params[k] = [v]

        new_query = urllib.parse.urlencode(query_params, doseq=True)
        redirect_url = urllib.parse.urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment,
            )
        )

        return RedirectResponse(
            url=redirect_url,
            status_code=status.HTTP_303_SEE_OTHER,
        )

    def verify_pkce(
        self,
        code_verifier: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> bool:
        """Verify the code verifier against the code challenge."""
        method = code_challenge_method.upper()
        if method == "PLAIN":
            if not settings.enable_plain_pkce:
                return False
            return secrets.compare_digest(code_verifier, code_challenge)
        elif method in ("S256", "SHA-256"):
            sha256_hash = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            calculated_challenge = base64.urlsafe_b64encode(sha256_hash).decode("utf-8").replace("=", "")
            return secrets.compare_digest(calculated_challenge, code_challenge)
        return False

    def _extract_client_credentials(
        self,
        auth_header: str | None,
        client_id: str | None,
        client_secret: str | None,
    ) -> tuple[str, str | None]:
        """Extract client ID and secret from Basic Auth header or parameters."""
        if auth_header and auth_header.startswith("Basic "):
            try:
                encoded_credentials = auth_header.split(" ", 1)[1]
                decoded_str = base64.b64decode(encoded_credentials).decode("utf-8")
                if ":" in decoded_str:
                    header_client_id, header_client_secret = decoded_str.split(":", 1)
                    if client_id and client_id != header_client_id:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="invalid_client",
                        )
                    return header_client_id, header_client_secret
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="invalid_client",
                )

        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_client",
            )
        return client_id, client_secret

    async def _process_authorization_code_grant(
        self,
        client: Client,
        token_service: TokenService,
        code: str | None,
        redirect_uri: str | None,
        code_verifier: str | None,
    ) -> dict:
        """Process authorization code grant type."""
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_request",
            )

        payload = await self.consume_authorization_code(code)
        if (
            not payload
            or payload["client_id"] != str(client.id)
            or payload.get("redirect_uri") != redirect_uri
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_grant",
            )

        code_challenge = payload.get("code_challenge")
        if code_challenge:
            if not code_verifier:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="invalid_grant",
                )
            code_challenge_method = payload.get("code_challenge_method", "S256")
            if not self.verify_pkce(code_verifier, code_challenge, code_challenge_method):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="invalid_grant",
                )

        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_grant",
            )
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_grant",
            )
        scope_str = payload.get("scope", "")

        access_token, expires_in = await token_service.generate_access_token(
            client_id=str(client.id),
            user_id=user_id,
            scope=scope_str,
        )

        refresh_token_str = await token_service.generate_refresh_token(
            client_id=client.id,
            user_id=user_uuid,
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": refresh_token_str,
            "scope": scope_str,
        }

    async def _process_client_credentials_grant(
        self,
        client: Client,
        token_service,
        scope: str | None,
    ) -> dict:
        """Process client credentials grant type."""
        requested_scope = scope or client.scope
        try:
            self.validate_scope(requested_scope, client)
        except InvalidScopeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_scope",
            )

        access_token, expires_in = await token_service.generate_access_token(
            client_id=str(client.id),
            user_id=None,
            scope=requested_scope,
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": requested_scope,
        }

    async def _process_refresh_token_grant(
        self,
        client: Client,
        token_service,
        refresh_token: str | None,
        scope: str | None,
    ) -> dict:
        """Process refresh token grant type."""
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_request",
            )

        token_record = await token_service.get_refresh_token(refresh_token)
        if not token_record or token_record.client_id != client.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_grant",
            )

        now = datetime.now(timezone.utc)
        expires_at = token_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_grant",
            )

        if token_record.is_revoked:
            await token_service.revoke_refresh_token_family(token_record.parent_family_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_grant",
            )

        await token_service.revoke_refresh_token(token_record.id)

        granted_scope = scope or client.scope
        if scope:
            try:
                self.validate_scope(scope, client)
            except InvalidScopeError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="invalid_scope",
                )

        access_token, expires_in = await token_service.generate_access_token(
            client_id=str(client.id),
            user_id=str(token_record.user_id),
            scope=granted_scope,
        )

        new_refresh_token = await token_service.generate_refresh_token(
            client_id=client.id,
            user_id=token_record.user_id,
            parent_family_id=token_record.parent_family_id,
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": new_refresh_token,
            "scope": granted_scope,
        }

    async def exchange_token(
        self,
        grant_type: str,
        token_service,
        auth_header: str | None = None,
        code: str | None = None,
        redirect_uri: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        code_verifier: str | None = None,
        refresh_token: str | None = None,
        scope: str | None = None,
    ) -> dict:
        """Exchange code or client credentials for tokens."""
        client_id, client_secret = self._extract_client_credentials(auth_header, client_id, client_secret)

        try:
            client = await self.authenticate_client(client_id, client_secret)
        except HTTPException as e:
            raise HTTPException(
                status_code=e.status_code,
                detail="invalid_client",
            )

        # Check if the requested grant type is supported by the client
        allowed_grants = client.grant_types.split(",") if client.grant_types else []
        if grant_type not in allowed_grants:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="unsupported_grant_type",
            )

        # 2. Process Grant Types
        if grant_type == "authorization_code":
            return await self._process_authorization_code_grant(
                client, token_service, code, redirect_uri, code_verifier
            )
        elif grant_type == "client_credentials":
            return await self._process_client_credentials_grant(client, token_service, scope)
        elif grant_type == "refresh_token":
            return await self._process_refresh_token_grant(client, token_service, refresh_token, scope)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="unsupported_grant_type",
            )

    async def _decode_and_validate_jwt(
        self, token: str, client_id_str: str, key_service: KeyService | None = None
    ) -> dict | None:
        """Decode a JWT, verify its signature with the corresponding public key,
        and validate it belongs to the client."""
        if not key_service:
            return None
        try:
            # 1. Parse unverified header to extract the key ID (kid)
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            if not kid:
                return None

            signing_key = await key_service.get_signing_key_by_kid(kid)
            if not signing_key:
                return None

            # 2. Verify the signature, audience, and expiration
            # PyJWT automatically validates audience, expiration, and signature.
            payload = jwt.decode(
                token,
                key=signing_key.public_key_pem,
                algorithms=[signing_key.algorithm],
                audience=client_id_str,
            )
            return payload
        except jwt.ExpiredSignatureError:
            # Token is already expired, so we don't need to blacklist it.
            pass
        except Exception:
            # Any other verification failure (e.g., invalid signature, malformed token)
            pass
        return None

    async def _blacklist_jwt(self, payload: dict) -> None:
        """Add JWT's jti to the Redis blacklist with TTL matching remaining lifespan."""
        jti = payload.get("jti")
        exp = payload.get("exp")
        if not jti or not exp:
            return
        now = int(datetime.now(timezone.utc).timestamp())
        ttl = int(exp) - now
        if ttl > 0:
            await self.redis_pool.setex(f"token:blacklist:{jti}", ttl, "true")

    async def _authenticate_client_for_revocation(
        self,
        auth_header: str | None,
        client_id: str | None,
        client_secret: str | None,
    ) -> Client:
        """Extract client credentials and authenticate the client for token revocation."""
        extracted_id, extracted_secret = self._extract_client_credentials(
            auth_header, client_id, client_secret
        )
        try:
            return await self.authenticate_client(extracted_id, extracted_secret)
        except HTTPException as e:
            raise HTTPException(
                status_code=e.status_code,
                detail="invalid_client",
            )

    async def _revoke_access_token(
        self,
        token: str,
        client_id_str: str,
        key_service: KeyService | None,
    ) -> bool:
        """Attempt to decode, validate, and blacklist an access token.
        Returns True if successful, False otherwise.
        """
        payload = await self._decode_and_validate_jwt(token, client_id_str, key_service)
        if payload:
            await self._blacklist_jwt(payload)
            return True
        return False

    async def _revoke_refresh_token(
        self,
        token: str,
        client_id: uuid.UUID,
        token_service: TokenService,
    ) -> bool:
        """Attempt to retrieve and revoke a refresh token and its family.
        Returns True if the token was found and revoked, False otherwise.
        """
        token_record = await token_service.get_refresh_token(token)
        if token_record and token_record.client_id == client_id:
            await token_service.revoke_refresh_token_family(token_record.parent_family_id)
            return True
        return False

    async def revoke_token(
        self,
        token: str,
        token_service: TokenService,
        key_service: KeyService | None = None,
        token_type_hint: str | None = None,
        auth_header: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> dict:
        """Revoke a token (access or refresh) based on the provided token string."""
        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_request",
            )

        if token_type_hint not in (None, "access_token", "refresh_token"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="unsupported_token_type",
            )

        # Authenticate the client
        client = await self._authenticate_client_for_revocation(auth_header, client_id, client_secret)
        client_id_str = str(client.id)

        # 1. If hint is "access_token", try access token first, then fallback to refresh token
        if token_type_hint == "access_token":
            if await self._revoke_access_token(token, client_id_str, key_service):
                return {}
            await self._revoke_refresh_token(token, client.id, token_service)
            return {}

        # 2. If hint is "refresh_token", try refresh token first, then fallback to access token
        if token_type_hint == "refresh_token":
            if await self._revoke_refresh_token(token, client.id, token_service):
                return {}
            await self._revoke_access_token(token, client_id_str, key_service)
            return {}

        # 3. No hint: try access token first, then fallback to refresh token
        if await self._revoke_access_token(token, client_id_str, key_service):
            return {}
        await self._revoke_refresh_token(token, client.id, token_service)

        # RFC 7009: Return empty dictionary to signal success without disclosing existence
        return {}


async def get_oauth_service(
    background_tasks: BackgroundTasks,
    client_repo: ClientRepository = Depends(get_client_repository),
    authorization_code_repo: AuthorizationCodeRepository = Depends(get_authorization_code_repo),
    redis: Redis = Depends(get_redis),
) -> OAuthService:
    """Dependency provider for OAuthService."""
    return OAuthService(
        client_repo=client_repo,
        authorization_code_repo=authorization_code_repo,
        background_tasks=background_tasks,
        redis_pool=redis,
    )
