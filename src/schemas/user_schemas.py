from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address of the new user")
    password: str = Field(..., min_length=8, max_length=128, description="Password for the new user")


class UserRegisterResponse(BaseModel):
    id: str
    email: EmailStr
    is_active: bool
    is_locked: bool
    created_at: str
    message: str
