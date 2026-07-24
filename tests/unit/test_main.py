from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.main_as import app


def test_root():
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the OAuth2.0 Authorization Server!"}


@patch("src.main_as.db_health_check", new_callable=AsyncMock)
@patch("src.main_as.redis_health_check", new_callable=AsyncMock)
def test_health_check_healthy(mock_redis_hc, mock_db_hc):
    mock_db_hc.return_value = True
    mock_redis_hc.return_value = True

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] is True
    assert data["redis"] is True
    assert "timestamp" in data


@patch("src.main_as.db_health_check", new_callable=AsyncMock)
@patch("src.main_as.redis_health_check", new_callable=AsyncMock)
def test_health_check_unhealthy(mock_redis_hc, mock_db_hc):
    mock_db_hc.return_value = False
    mock_redis_hc.return_value = True

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "unhealthy"
    assert data["database"] is False
    assert data["redis"] is True
