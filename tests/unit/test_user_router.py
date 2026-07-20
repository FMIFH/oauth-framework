import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.main_as import app
from src.models import User
from src.repositories.user_repo import UserRepository, get_user_repository


@pytest.fixture
def mock_user_repo():
    repo = AsyncMock(spec=UserRepository)
    return repo


@pytest.fixture
def client(mock_user_repo):
    # Override dependency
    app.dependency_overrides[get_user_repository] = lambda: mock_user_repo
    with TestClient(app) as c:
        yield c
    # Clean up overrides
    app.dependency_overrides.clear()


def test_register_user_success(client, mock_user_repo):
    # Arrange
    email = "new_user@example.com"
    password = "securepassword123"

    # Mock return value of get_by_email to be None (user doesn't exist)
    mock_user_repo.get_by_email.return_value = None

    # Mock created user
    created_user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash="hashed_password",
        is_active=True,
        is_locked=False,
        created_at=datetime.now(timezone.utc),
    )
    mock_user_repo.create_user.return_value = created_user

    # Act
    response = client.post(
        "/users/register",
        json={"email": email, "password": password},
    )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == email
    assert data["is_active"] is True
    assert data["message"] == "User registered successfully"
    mock_user_repo.get_by_email.assert_called_once_with(email)
    mock_user_repo.create_user.assert_called_once()


def test_register_user_already_exists(client, mock_user_repo):
    # Arrange
    email = "existing@example.com"
    password = "securepassword123"

    # Mock existing user
    mock_user_repo.get_by_email.return_value = User(email=email, password_hash="hash")

    # Act
    response = client.post(
        "/users/register",
        json={"email": email, "password": password},
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Email already registered"
    mock_user_repo.create_user.assert_not_called()


def test_register_user_validation_error(client):
    # Act - Password too short
    response = client.post(
        "/users/register",
        json={"email": "invalid@example.com", "password": "short"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Act - Invalid email
    response = client.post(
        "/users/register",
        json={"email": "invalid-email", "password": "securepassword123"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_register_user_internal_error(client, mock_user_repo):
    # Arrange
    email = "error@example.com"
    password = "securepassword123"

    # Mock get_by_email to raise an exception
    mock_user_repo.get_by_email.side_effect = Exception("Database is down")

    # Act
    response = client.post(
        "/users/register",
        json={"email": email, "password": password},
    )

    # Assert
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Database is down" in response.json()["detail"]


def test_login_page_renders(client):
    # Act
    response = client.get("/users/login?client_id=test-client")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert "Sign In" in response.text
    assert 'name="client_id" value="test-client"' in response.text


def test_login_success_without_oauth(client, mock_user_repo):
    # Arrange
    from src.core.security import hash_password

    email = "user@example.com"
    password = "correct_password"

    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        is_locked=False,
        created_at=datetime.now(timezone.utc),
    )
    mock_user_repo.get_by_email.return_value = user

    # Act
    response = client.post(
        "/users/login",
        data={"email": email, "password": password},
    )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Login successful"
    assert response.json()["user_id"] == str(user.id)
    # Check that cookie was set
    assert "user_session" in response.cookies


def test_login_success_with_oauth(client, mock_user_repo):
    # Arrange
    from src.core.security import hash_password

    email = "user@example.com"
    password = "correct_password"

    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        is_locked=False,
        created_at=datetime.now(timezone.utc),
    )
    mock_user_repo.get_by_email.return_value = user

    # Act
    response = client.post(
        "/users/login",
        data={
            "email": email,
            "password": password,
            "client_id": "test-client",
            "redirect_uri": "http://localhost/callback",
            "response_type": "code",
        },
        follow_redirects=False,
    )

    # Assert (Should redirect back to authorize endpoint)
    assert response.status_code == status.HTTP_303_SEE_OTHER
    location = response.headers["location"]
    assert "/oauth/authorize" in location
    assert "client_id=test-client" in location
    assert "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback" in location


def test_login_failure(client, mock_user_repo):
    # Arrange
    mock_user_repo.get_by_email.return_value = None

    # Act
    response = client.post(
        "/users/login",
        data={"email": "wrong@example.com", "password": "wrong_password"},
        follow_redirects=False,
    )

    # Assert (Should redirect back to login page with error query param)
    assert response.status_code == status.HTTP_303_SEE_OTHER
    location = response.headers["location"]
    assert "/users/login" in location
    assert "error=Invalid+email+or+password" in location
