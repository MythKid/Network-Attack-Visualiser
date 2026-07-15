"""Network Attack Visualiser — backend application package.

Phase 1 (Backend Skeleton): provides the FastAPI application factory
(:mod:`app.main`), environment-driven settings (:mod:`app.config`) and the health
endpoint (:mod:`app.api`). Detection, ingest, storage, alerting and the AI layer
are introduced in later approved phases — see ``docs/DEVELOPMENT_PHASES.md``.

``__version__`` is the default source for the reported application version:
:class:`app.config.Settings` defaults ``app_version`` to it, while the
``APP_VERSION`` environment variable can override the value at runtime.
"""

__version__: str = "0.1.0"
