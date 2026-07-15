"""Tests for the health endpoint and the OpenAPI/docs surface."""

import pytest
from fastapi.testclient import TestClient

import app
from app.api.schemas import HealthResponse
from app.config import Settings
from app.main import create_app

TEST_APP_NAME = "NAV Test App"
TEST_VERSION = "9.9.9-test"


@pytest.fixture
def settings() -> Settings:
    """Isolated settings with distinctive name/version for assertions."""
    return Settings(_env_file=None, app_name=TEST_APP_NAME, app_version=TEST_VERSION)


@pytest.fixture
def client(settings: Settings) -> TestClient:
    """A TestClient bound to an app built from the injected settings."""
    return TestClient(create_app(settings))


def test_health_returns_200_ok(client: TestClient) -> None:
    """GET /health responds 200 with the expected body."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": TEST_VERSION}


def test_health_matches_response_schema(client: TestClient) -> None:
    """The health body validates against the typed HealthResponse model."""
    response = client.get("/health")

    model = HealthResponse.model_validate(response.json())

    assert model.status == "ok"
    assert model.version == TEST_VERSION


def test_health_version_defaults_to_package_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no override, the reported version is the packaged ``app.__version__``."""
    monkeypatch.delenv("APP_VERSION", raising=False)
    default_settings = Settings(_env_file=None)

    client = TestClient(create_app(default_settings))

    assert client.get("/health").json()["version"] == app.__version__


def test_openapi_exposes_metadata(client: TestClient) -> None:
    """The OpenAPI schema is served and reflects the configured metadata."""
    response = client.get("/openapi.json")

    assert response.status_code == 200
    info = response.json()["info"]
    assert info["title"] == TEST_APP_NAME
    assert info["version"] == TEST_VERSION


def test_docs_are_available(client: TestClient) -> None:
    """The interactive API docs render at /docs."""
    response = client.get("/docs")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
