"""Browser CORS policy tests (SEC_REQ §4.2): exact allowlist, no wildcard."""

from fastapi.testclient import TestClient

ALLOWED_ORIGIN = "http://localhost:5173"
DISALLOWED_ORIGIN = "http://evil.example"


def test_allowed_origin_receives_exact_allow_header(client: TestClient) -> None:
    response = client.get("/api/v1/alerts", headers={"Origin": ALLOWED_ORIGIN})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    # Never a wildcard, and credentialed CORS is disabled entirely.
    assert response.headers.get("access-control-allow-origin") != "*"
    assert "access-control-allow-credentials" not in response.headers


def test_disallowed_origin_receives_no_allow_headers(client: TestClient) -> None:
    response = client.get("/api/v1/alerts", headers={"Origin": DISALLOWED_ORIGIN})
    assert response.status_code == 200  # the data still serves; the BROWSER blocks
    assert "access-control-allow-origin" not in response.headers


def test_preflight_for_allowed_origin_and_method(client: TestClient) -> None:
    response = client.options(
        "/api/v1/alerts",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    assert "GET" in response.headers.get("access-control-allow-methods", "")


def test_preflight_for_disallowed_origin_is_refused(client: TestClient) -> None:
    response = client.options(
        "/api/v1/alerts",
        headers={
            "Origin": DISALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_preflight_for_disallowed_method_is_refused(client: TestClient) -> None:
    """The browser never calls write methods; none are offered to it."""
    response = client.options(
        "/api/v1/alerts",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "DELETE",
        },
    )
    assert response.status_code == 400
