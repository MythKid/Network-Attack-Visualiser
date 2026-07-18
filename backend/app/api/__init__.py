"""HTTP API layer for the Network Attack Visualiser backend.

Phase 1 provided the health endpoint; Phase 3 adds the alert and statistics
read endpoints, the authenticated ingest endpoint with its body-size
middleware, and the ``WS /api/v1/ws/alerts`` live delta feed. The full
REST/WebSocket contract is documented in ``docs/API.md``.
"""
