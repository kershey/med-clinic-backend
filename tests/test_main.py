"""
Tests for the main application endpoints.
"""
from fastapi.testclient import TestClient

def test_root_endpoint(client):
    """
    Test the root endpoint returns a welcome message.
    """
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data


def test_health_check(client):
    """
    Test the health check endpoint returns a healthy status.
    """
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "database" in data 