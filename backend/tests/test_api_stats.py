"""``GET /api/v1/stats`` contract tests (per-provenance buckets, scoping)."""

import inspect

from fastapi.testclient import TestClient

from app.api import stats as stats_api
from app.ingest.synthetic import port_scan
from tests.factories import auth_headers, ingest_payload, make_alert

ALL_SEVERITIES = {"low", "medium", "high", "critical"}
ALL_SOURCE_TYPES = {"synthetic", "replay", "live"}


def seed_stats(client: TestClient, buckets: dict[tuple[float, str, str], tuple[int, int]]) -> None:
    """Insert event_stats rows directly through the app's own repository."""
    database = client.app.state.database  # type: ignore[attr-defined]
    repository = client.app.state.stats_repository  # type: ignore[attr-defined]
    with database.transaction():
        repository.upsert(buckets)


def seed_alerts(client: TestClient, *alerts: object) -> None:
    database = client.app.state.database  # type: ignore[attr-defined]
    repository = client.app.state.alert_repository  # type: ignore[attr-defined]
    with database.transaction():
        for alert in alerts:
            repository.insert(alert)


def test_stats_route_is_synchronous_def() -> None:
    """The whole snapshot (read session included) runs on one worker thread."""
    assert not inspect.iscoroutinefunction(stats_api.get_stats)


def test_empty_database_returns_zero_filled_keys(client: TestClient) -> None:
    body = client.get("/api/v1/stats").json()
    assert body["totals"] == {
        "alert_count": 0,
        "alert_occurrence_total": 0,
        "event_count": 0,
        "byte_count": 0,
    }
    assert set(body["alerts_by_severity"]) == ALL_SEVERITIES
    assert set(body["alerts_by_detector"]) == {"portscan", "synflood"}
    assert set(body["alerts_by_source_type"]) == ALL_SOURCE_TYPES
    assert all(count == 0 for count in body["alerts_by_severity"].values())
    assert body["protocol_distribution"] == []
    assert body["traffic_timeline"] == []


def test_ingested_scan_populates_every_section(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=20)),
        headers=auth_headers(),
    )
    assert response.status_code == 202
    body = client.get("/api/v1/stats").json()
    assert body["totals"]["alert_count"] == 1
    assert body["totals"]["alert_occurrence_total"] == 1
    assert body["totals"]["event_count"] == 20
    assert body["alerts_by_detector"]["portscan"] == 1
    assert body["alerts_by_severity"]["medium"] == 1
    assert body["alerts_by_source_type"]["synthetic"] == 1
    assert body["protocol_distribution"][0]["protocol"] == "TCP"
    assert body["traffic_timeline"], "timeline must not be empty after ingest"


def test_occurrence_total_diverges_from_alert_count_after_reinforcement(
    client: TestClient,
) -> None:
    """'3 alerts' and '7 triggers' are different facts; expose both."""
    for start in (1000.0, 1014.0):  # second scan re-arms the latch, within cooldown
        client.post(
            "/api/v1/ingest/events",
            json=ingest_payload(port_scan(start_ts=start, num_ports=20)),
            headers=auth_headers(),
        )
    totals = client.get("/api/v1/stats").json()["totals"]
    assert totals["alert_count"] == 1
    assert totals["alert_occurrence_total"] == 2


def test_timeline_buckets_are_selected_per_provenance(client: TestClient) -> None:
    """Regression: live timestamps must not crowd out synthetic buckets."""
    seed_stats(
        client,
        {
            (1000.0, "TCP", "synthetic"): (5, 320),
            (1001.0, "TCP", "synthetic"): (7, 448),
            (1002.0, "TCP", "synthetic"): (9, 576),
            (1.7e9, "TCP", "live"): (3, 192),
            (1.7e9 + 1, "TCP", "live"): (4, 256),
        },
    )
    timeline = client.get("/api/v1/stats", params={"buckets": 2}).json()["traffic_timeline"]
    by_source = {row["source_type"] for row in timeline}
    assert by_source == {"synthetic", "live"}  # synthetic did NOT vanish
    synthetic_ts = [r["bucket_ts"] for r in timeline if r["source_type"] == "synthetic"]
    assert synthetic_ts == [1001.0, 1002.0]  # its own latest two seconds


def test_source_type_filter_scopes_every_section(client: TestClient) -> None:
    seed_alerts(
        client,
        make_alert(source_type="synthetic"),
        make_alert(source_type="live", severity="high"),
    )
    seed_stats(
        client,
        {
            (1000.0, "TCP", "synthetic"): (5, 320),
            (1.7e9, "UDP", "live"): (3, 192),
        },
    )
    body = client.get("/api/v1/stats", params={"source_type": "synthetic"}).json()
    assert body["totals"]["alert_count"] == 1
    assert body["totals"]["event_count"] == 5
    assert body["alerts_by_source_type"] == {"synthetic": 1, "replay": 0, "live": 0}
    assert body["alerts_by_severity"]["high"] == 0  # the live alert is out of scope
    assert [row["protocol"] for row in body["protocol_distribution"]] == ["TCP"]
    assert {row["source_type"] for row in body["traffic_timeline"]} == {"synthetic"}


def test_snapshot_sections_are_mutually_consistent(client: TestClient) -> None:
    seed_alerts(
        client,
        make_alert(severity="medium"),
        make_alert(severity="high"),
        make_alert(severity="high", source_type="live"),
    )
    body = client.get("/api/v1/stats").json()
    assert sum(body["alerts_by_severity"].values()) == body["totals"]["alert_count"]
    assert sum(body["alerts_by_source_type"].values()) == body["totals"]["alert_count"]
    assert sum(body["alerts_by_detector"].values()) == body["totals"]["alert_count"]


def test_buckets_parameter_is_validated(client: TestClient) -> None:
    assert client.get("/api/v1/stats", params={"buckets": 0}).status_code == 422
    assert client.get("/api/v1/stats", params={"buckets": 3601}).status_code == 422
    assert client.get("/api/v1/stats", params={"source_type": "psychic"}).status_code == 422
