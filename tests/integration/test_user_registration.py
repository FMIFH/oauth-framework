import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.core.database import get_db
from src.main_as import app
from src.models import User


class FakeAsyncSession:
    """An in-memory fake AsyncSession to test endpoints end-to-end without a database."""

    def __init__(self):
        self.users = {}

    def add(self, instance):
        if isinstance(instance, User):
            if not instance.id:
                instance.id = uuid.uuid4()
            if not instance.created_at:
                instance.created_at = datetime.now(timezone.utc)
            if instance.is_locked is None:
                instance.is_locked = False
            self.users[instance.id] = instance

    async def commit(self):
        pass

    async def refresh(self, instance):
        pass

    async def execute(self, statement):
        # Compile statement to get the parameters
        compiled = statement.compile()
        params = compiled.params

        email = None
        user_id = None

        # Look up parameters by substring or standard SQLAlchemy naming convention
        for key, value in params.items():
            if "email" in key:
                email = value
            elif "id" in key:
                user_id = value

        mock_result = MagicMock()
        if email:
            found_user = next((u for u in self.users.values() if u.email == email), None)
            mock_result.scalar_one_or_none.return_value = found_user
        elif user_id:
            # Handle uuid lookup
            if isinstance(user_id, str):
                try:
                    user_id = uuid.UUID(user_id)
                except ValueError:
                    pass
            found_user = self.users.get(user_id)
            mock_result.scalar_one_or_none.return_value = found_user
        else:
            mock_result.scalar_one_or_none.return_value = None

        return mock_result

    async def close(self):
        pass


@pytest.fixture
def fake_session():
    return FakeAsyncSession()


@pytest.fixture
def client(fake_session):
    async def override_get_db():
        yield fake_session

    # Override get_db dependency to use our fake in-memory session
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_integration_user_registration_flow(client, fake_session):
    # 1. Register a new user
    email = "integration_test@example.com"
    password = "supersecurepassword123"

    response = client.post(
        "/users/register",
        json={"email": email, "password": password},
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == email
    assert data["is_active"] is True
    assert data["is_locked"] is False
    assert data["message"] == "User registered successfully"
    assert "id" in data

    # Verify that the user was actually saved in our fake database session
    assert len(fake_session.users) == 1
    saved_user = list(fake_session.users.values())[0]
    assert saved_user.email == email

    # 2. Try to register the exact same email again and verify it's blocked (400 Bad Request)
    dup_response = client.post(
        "/users/register",
        json={"email": email, "password": "anotherpassword123"},
    )
    assert dup_response.status_code == status.HTTP_400_BAD_REQUEST
    assert dup_response.json()["detail"] == "Email already registered"

    # Verify no second user was created
    assert len(fake_session.users) == 1


def test_integration_user_registration_invalid_inputs(client):
    # 1. Invalid email
    response = client.post(
        "/users/register",
        json={"email": "not-an-email", "password": "password123"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # 2. Password too short
    response = client.post(
        "/users/register",
        json={"email": "valid@example.com", "password": "short"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_integration_register_multiple_distinct_users(client, fake_session):
    emails = ["user1@example.com", "user2@example.com", "user3@example.com"]

    for email in emails:
        response = client.post(
            "/users/register",
            json={"email": email, "password": "securepassword123"},
        )
        assert response.status_code == status.HTTP_201_CREATED

    assert len(fake_session.users) == 3
    stored_emails = {u.email for u in fake_session.users.values()}
    assert stored_emails == set(emails)
