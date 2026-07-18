"""SQLite persistence for alerts and pre-aggregated event statistics.

Phase 3 provides one :class:`~app.storage.database.Database` (the sole owner of
the sqlite3 connection and its lock), the schema from ``docs/ALERT_SCHEMA.md``
§4, and the :class:`~app.storage.alerts.AlertRepository` /
:class:`~app.storage.stats.EventStatsRepository` repositories that share it.
"""

from app.storage.alerts import AlertRepository
from app.storage.database import (
    SCHEMA_SQL,
    Database,
    connect,
    dumps_finite,
    initialise_schema,
    loads_finite,
)
from app.storage.stats import (
    EventStatsRepository,
    ProtocolCount,
    StatsBuckets,
    TimelineBucket,
    aggregate_event_stats,
)

__all__ = [
    "SCHEMA_SQL",
    "AlertRepository",
    "Database",
    "EventStatsRepository",
    "ProtocolCount",
    "StatsBuckets",
    "TimelineBucket",
    "aggregate_event_stats",
    "connect",
    "dumps_finite",
    "initialise_schema",
    "loads_finite",
]
