import typing
import urllib.parse

from fastapi import APIRouter, Depends, Form, HTTPException, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from src.core.security import hash_password, verify_password
from src.repositories.user_repo import UserRepository, get_user_repository
from src.schemas.user_schemas import UserRegisterRequest, UserRegisterResponse

router = APIRouter(
    prefix="/users",
    tags=["users"],
)


@router.post(
    "/register",
    response_model=UserRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    body: UserRegisterRequest,
    user_repo: UserRepository = Depends(get_user_repository),
):
    try:
        # Check if email is already registered
        existing_user = await user_repo.get_by_email(body.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        # Hash the password
        password_hash = hash_password(body.password)

        # Create the user
        user = await user_repo.create_user(email=body.email, password_hash=password_hash, is_active=True)

        return UserRegisterResponse(
            id=str(user.id),
            email=user.email,
            is_active=user.is_active,
            is_locked=user.is_locked,
            created_at=user.created_at.isoformat(),
            message="User registered successfully",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while registering the user: {str(e)}",
        )


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    response_type: str | None = None,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    scope: str | None = None,
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    error: str | None = None,
):
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - OAuth Server</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 flex items-center justify-center min-h-screen">
    <div class="max-w-md w-full bg-white rounded-lg shadow-md p-8 border border-gray-100">
        <div class="text-center mb-6">
            <h1 class="text-2xl font-bold text-gray-900">Sign In</h1>
            <p class="text-gray-500 text-sm mt-1">Access your OAuth Authorization Server account</p>
        </div>

        {f'<div class="bg-red-50 border-l-4 border-red-500 p-4 mb-4 text-sm text-red-700 rounded" role="alert">{error}</div>' if error else ""}

        <form action="/users/login" method="POST" class="space-y-4">
            <input type="hidden" name="response_type" value="{response_type or ""}">
            <input type="hidden" name="client_id" value="{client_id or ""}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri or ""}">
            <input type="hidden" name="scope" value="{scope or ""}">
            <input type="hidden" name="state" value="{state or ""}">
            <input type="hidden" name="code_challenge" value="{code_challenge or ""}">
            <input type="hidden" name="code_challenge_method" value="{code_challenge_method or ""}">

            <div>
                <label for="email" class="block text-sm font-medium text-gray-700">Email Address</label>
                <input type="email" id="email" name="email" required class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>

            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" id="password" name="password" required class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>

            <button type="submit" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                Sign In
            </button>
        </form>
    </div>
</body>
</html>"""  # noqa: E501
    return html_content


@router.post("/login")
async def login(
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    response_type: str | None = Form(None),
    client_id: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    scope: str | None = Form(None),
    state: str | None = Form(None),
    code_challenge: str | None = Form(None),
    code_challenge_method: str | None = Form(None),
    user_repo: UserRepository = Depends(get_user_repository),
):
    # Retrieve user
    user = await user_repo.get_by_email(email)

    # Check credentials
    if not user or not verify_password(password, user.password_hash):
        params = {"error": "Invalid email or password"}
        if response_type:
            params["response_type"] = response_type
        if client_id:
            params["client_id"] = client_id
        if redirect_uri:
            params["redirect_uri"] = redirect_uri
        if scope:
            params["scope"] = scope
        if state:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method

        query_string = urllib.parse.urlencode(params)
        return RedirectResponse(
            url=f"/users/login?{query_string}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # Successful login: Set user session cookie
    response.set_cookie(
        key="user_session",
        value=str(user.id),
        httponly=True,
        max_age=3600,  # 1 hour
        samesite="lax",
    )

    # If part of OAuth authorize flow, redirect back to authorize
    if client_id and redirect_uri:
        raw_params = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        auth_params = typing.cast(dict[str, str], {k: v for k, v in raw_params.items() if v is not None})
        query_string = urllib.parse.urlencode(auth_params)
        redirect_response = RedirectResponse(
            url=f"/oauth/authorize?{query_string}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        redirect_response.set_cookie(
            key="user_session",
            value=str(user.id),
            httponly=True,
            max_age=3600,  # 1 hour
            samesite="lax",
        )
        return redirect_response

    return {"message": "Login successful", "user_id": str(user.id)}
