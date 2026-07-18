"""Network Attack Visualiser — backend application package.

Phase 1 (Backend Skeleton) provides the FastAPI application factory
(:mod:`app.main`), environment-driven settings (:mod:`app.config`) and the health
endpoint (:mod:`app.api`). Phase 2 (Detection Engine + Synthetic Events) adds the
typed domain schemas (:mod:`app.models`), the clock-injected detectors and engine
(:mod:`app.detection`) and the synthetic event generator (:mod:`app.ingest`).
Phase 3 (Alert Pipeline) adds SQLite storage (:mod:`app.storage`), the Alert
Engine with its cooldown/deduplication gate, the event pipeline and the WebSocket
broadcaster (:mod:`app.alerts`), and the alert, statistics, ingest and WebSocket
API routes (:mod:`app.api`). The frontend, PCAP replay, live capture and the AI
layer are introduced in later phases — see ``docs/DEVELOPMENT_PHASES.md``.

``__version__`` is the default source for the reported application version:
:class:`app.config.Settings` defaults ``app_version`` to it, while the
``APP_VERSION`` environment variable can override the value at runtime.
"""

__version__: str = "0.3.0"
