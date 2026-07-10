import pytest
import boto3
from moto import mock_aws
from app import app  # import your actual Flask app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

# ── GOOD: Dashboard loads successfully ──────────────────────────────────────
def test_dashboard_loads(client):
    """Dashboard route returns 200 OK"""
    response = client.get("/")
    assert response.status_code == 200

# ── GOOD: API returns findings ───────────────────────────────────────────────
@mock_aws
def test_api_returns_findings(client):
    """API endpoint returns findings list"""
    ec2 = boto3.client("ec2", region_name="ca-central-1")
    ec2.create_volume(AvailabilityZone="ca-central-1a", Size=10, Encrypted=False)

    response = client.get("/api/findings")  # adjust to your actual route
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)

# ── BAD: Invalid route returns 404 ──────────────────────────────────────────
def test_invalid_route_returns_404(client):
    """Non-existent route should return 404"""
    response = client.get("/this-does-not-exist")
    assert response.status_code == 404