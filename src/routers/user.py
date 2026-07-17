from fastapi import APIRouter, Depends, HTTPException, status

from src.core.security import hash_password
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
        user = await user_repo.create_user(
            email=body.email, password_hash=password_hash, is_active=True
        )

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

