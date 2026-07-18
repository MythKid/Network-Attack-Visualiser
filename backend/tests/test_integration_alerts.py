"""End-to-end integration: ingest → detection → SQLite → REST (+ concurrency).

These tests drive the complete documented pipeline through the public API of a
lifespan-started application over a real temporary-file database.
"""

import threading
from collections.abc import Sequence
from typing import Any

from fastapi.testclient import TestClient

from app.ingest.synthetic import normal_traffic, port_scan, syn_burst
from app.models.packet_event import PacketEvent
from tests.factories import auth_headers, ingest_payload

JOIN_TIMEOUT_S = 15.0


def post_events(client: TestClient, events: Sequence[PacketEvent]) -> Any:
    return client.post(
        "/api/v1/ingest/events",
        json=ingest_payload(events),
        headers=auth_headers(),
    )


def test_ingest_to_rest_headline_flow(client: TestClient) -> None:
    """The Phase 3 acceptance criterion: ingest -> detection -> row -> REST."""
    response = post_events(client, port_scan(num_ports=20))
    assert response.status_code == 202

    listing = client.get("/api/v1/alerts").json()
    assert listing["total"] == 1
    alert = listing["items"][0]
    assert alert["detector_id"] == "portscan"
    assert alert["category"] == "reconnaissance"
    assert alert["source_type"] == "synthetic"
    assert alert["evidence"]["distinct_port_count"] >= 15
    assert alert["threshold_snapshot"]["PORTSCAN_MIN_PORTS"] == 15
    assert alert["occurrence_count"] == 1
    assert alert["ai_status"] == "none"

    detail = client.get(f"/api/v1/alerts/{alert['alert_id']}")
    assert detail.status_code == 200
    assert detail.json() == alert

    stats = client.get("/api/v1/stats").json()
    assert stats["totals"]["alert_count"] == 1
    assert stats["totals"]["event_count"] == 20


def test_normal_traffic_never_alerts(client: TestClient) -> None:
    response = post_events(client, normal_traffic())
    assert response.status_code == 202
    assert client.get("/api/v1/alerts").json()["total"] == 0


def test_syn_burst_produces_synflood_alert(client: TestClient) -> None:
    post_events(client, syn_burst(num_syns=120))
    listing = client.get("/api/v1/alerts").json()
    assert listing["total"] == 1
    alert = listing["items"][0]
    assert alert["detector_id"] == "synflood"
    assert alert["category"] == "dos"
    assert alert["src_ip"] is None  # destination-keyed detector
    assert alert["evidence"]["syn_count"] >= 100
    assert alert["evidence"]["completion_ratio"] == 0.0


def test_cooldown_update_and_new_row_lifecycle(client: TestClient) -> None:
    """The full documented lifecycle across three ingest batches.

    Scan at t=1000 creates; a re-armed scan at t=1014 (inside the 60s cooldown)
    updates the same row; a scan at t=1100 (cooldown elapsed) creates a second
    row — the dedup key never permanently suppresses.
    """
    first = post_events(client, port_scan(start_ts=1000.0, num_ports=20)).json()
    assert (first["alerts_created"], first["alerts_updated"]) == (1, 0)

    second = post_events(client, port_scan(start_ts=1014.0, num_ports=20)).json()
    assert (second["alerts_created"], second["alerts_updated"]) == (0, 1)

    listing = client.get("/api/v1/alerts").json()
    assert listing["total"] == 1
    reinforced = listing["items"][0]
    assert reinforced["occurrence_count"] == 2
    assert reinforced["created_at"] <= reinforced["last_seen"]
    assert reinforced["window_start"] == 1000.0  # spans the whole episode

    third = post_events(client, port_scan(start_ts=1100.0, num_ports=20)).json()
    assert (third["alerts_created"], third["alerts_updated"]) == (1, 0)
    assert client.get("/api/v1/alerts").json()["total"] == 2


def test_reads_during_ingest_stay_internally_consistent(client: TestClient) -> None:
    """Every /alerts response satisfies its own page/total invariant under load."""
    stop = threading.Event()
    violations: list[str] = []

    def reader() -> None:
        while not stop.is_set():
            body = client.get("/api/v1/alerts", params={"limit": 200}).json()
            if len(body["items"]) != body["total"]:
                violations.append(f"page/total mismatch: {len(body['items'])} != {body['total']}")

    reader_thread = threading.Thread(target=reader)
    reader_thread.start()
    try:
        # Distinct source AND destination per batch: fully independent detector
        # keys, so each batch is exactly one new portscan row (and the shared-
        # destination SYN total can never cross the synflood threshold).
        for index in range(8):
            response = post_events(
                client,
                port_scan(client=f"10.8.{index}.1", server=f"10.8.{index}.2", num_ports=20),
            )
            assert response.status_code == 202
    finally:
        stop.set()
        reader_thread.join(timeout=JOIN_TIMEOUT_S)
    assert not reader_thread.is_alive()
    assert violations == []
    assert client.get("/api/v1/alerts").json()["total"] == 8
