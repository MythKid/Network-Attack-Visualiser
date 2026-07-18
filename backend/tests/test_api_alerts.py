"""``GET /api/v1/alerts`` and ``GET /api/v1/alerts/{id}`` contract tests."""

import inspect
import uuid

from fastapi.testclient import TestClient

from app.api import alerts as alerts_api
from tests.factories import make_alert


def seed(client: TestClient, *alerts: object) -> None:
    """Insert alert rows directly through the app's own repository."""
    database = client.app.state.database  # type: ignore[attr-defined]
    repository = client.app.state.alert_repository  # type: ignore[attr-defined]
    with database.transaction():
        for alert in alerts:
            repository.insert(alert)


def test_read_routes_are_synchronous_def() -> None:
    """Sync routes run on the threadpool, keeping sqlite3 off the event loop."""
    assert not inspect.iscoroutinefunction(alerts_api.list_alerts)
    assert not inspect.iscoroutinefunction(alerts_api.get_alert)


def test_empty_database_lists_nothing(client: TestClient) -> None:
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    body = response.json()
    assert body == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_list_orders_newest_recorded_first_across_provenances(client: TestClient) -> None:
    """Recording order, not event time: mixed timelines must not reorder."""
    a = make_alert(created_at=1000.0, source_type="synthetic")
    b = make_alert(created_at=1.7e9, source_type="live")
    c = make_alert(created_at=1001.0, source_type="synthetic")
    seed(client, a, b, c)
    items = client.get("/api/v1/alerts").json()["items"]
    assert [item["alert_id"] for item in items] == [c.alert_id, b.alert_id, a.alert_id]


def test_filters_apply_and_total_matches(client: TestClient) -> None:
    seed(
        client,
        make_alert(severity="medium", source_type="synthetic"),
        make_alert(severity="high", source_type="synthetic"),
        make_alert(
            severity="high",
            source_type="live",
            detector_id="synflood",
            category="dos",
            src_ip=None,
        ),
    )
    high = client.get("/api/v1/alerts", params={"severity": "high"}).json()
    assert high["total"] == 2
    assert all(item["severity"] == "high" for item in high["items"])

    live_dos = client.get(
        "/api/v1/alerts",
        params={"source_type": "live", "category": "dos", "detector_id": "synflood"},
    ).json()
    assert live_dos["total"] == 1
    assert live_dos["items"][0]["src_ip"] is None


def test_pagination_is_consistent_within_one_response(client: TestClient) -> None:
    seed(client, *(make_alert(created_at=1000.0 + i) for i in range(5)))
    page = client.get("/api/v1/alerts", params={"limit": 2, "offset": 2}).json()
    assert page["total"] == 5
    assert len(page["items"]) == 2
    assert (page["limit"], page["offset"]) == (2, 2)

    beyond = client.get("/api/v1/alerts", params={"limit": 2, "offset": 10}).json()
    assert beyond["total"] == 5
    assert beyond["items"] == []


def test_invalid_query_parameters_are_422(client: TestClient) -> None:
    for params in (
        {"severity": "catastrophic"},
        {"detector_id": "mystery"},
        {"source_type": "psychic"},
        {"category": "weather"},
        {"limit": "0"},
        {"limit": "201"},
        {"offset": "-1"},
    ):
        assert client.get("/api/v1/alerts", params=params).status_code == 422, params


def test_get_alert_by_id(client: TestClient) -> None:
    alert = make_alert()
    seed(client, alert)
    response = client.get(f"/api/v1/alerts/{alert.alert_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == alert.alert_id
    assert body["evidence"] == alert.evidence
    assert body["ai_status"] == "none"


def test_get_unknown_alert_is_404(client: TestClient) -> None:
    assert client.get(f"/api/v1/alerts/{uuid.uuid4()}").status_code == 404


def test_get_malformed_alert_id_is_422(client: TestClient) -> None:
    assert client.get("/api/v1/alerts/not-a-uuid").status_code == 422
    # A UUID of the wrong version is not a valid alert id either.
    v1 = uuid.uuid1()
    assert client.get(f"/api/v1/alerts/{v1}").status_code == 422
