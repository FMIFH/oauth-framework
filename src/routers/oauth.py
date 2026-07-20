from fastapi import APIRouter, Depends, Form, Query, Request

from src.core.database import get_db
from src.services.key_manager import jwks
from src.services.oauth_service import OAuthService, get_oauth_service
from src.services.token_service import TokenService, get_token_service

router = APIRouter(prefix="/oauth", tags=["oauth"])


@router.get("/authorize")
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(...),
    state: str = Query(...),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(...),
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    user_id = request.cookies.get("user_session")
    return await oauth_service.process_authorization_request(
        user_id=user_id,
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


@router.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    code_verifier: str | None = Form(None),
    refresh_token: str | None = Form(None),
    scope: str | None = Form(None),
    oauth_service: OAuthService = Depends(get_oauth_service),
    token_service: TokenService = Depends(get_token_service),
):
    auth_header = request.headers.get("Authorization")
    return await oauth_service.exchange_token(
        grant_type=grant_type,
        token_service=token_service,
        auth_header=auth_header,
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
        code_verifier=code_verifier,
        refresh_token=refresh_token,
        scope=scope,
    )


@router.get("/jwks")
async def jwks_endpoints(session=Depends(get_db)):
    return await jwks(session=session)
