import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from src.core.database import get_db
from src.exceptions.invalid_scope_exception import InvalidScopeException
from src.services.key_manager import jwks
from src.services.oauth_service import OAuthService, get_oauth_service

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

    # 1. User is authenticated, validate OAuth client & redirect URI
    client = await oauth_service.get_and_validate_client(client_id, redirect_uri)

    # Validate the requested scope
    try:
        oauth_service.validate_scope(scope, client)
    except InvalidScopeException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # 2. Check if user is authenticated via cookie
    user_id = request.cookies.get("user_session")
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
    code = await oauth_service.create_authorization_code(
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


@router.post("/token")
def token():
    return {"message": "Token endpoint"}


@router.get("/jwks")
async def jwks_endpoints(session=Depends(get_db)):
    return await jwks(session=session)
