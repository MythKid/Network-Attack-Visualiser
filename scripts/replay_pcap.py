#!/usr/bin/env python3
"""Replay a PCAP into the detection pipeline (Phase 5), unprivileged and in-process.

This is a thin runner over :func:`app.ingest.pcap_replay.replay_pcap`. It builds
the same pipeline the backend uses — SQLite storage, both detectors, the alert
gate and statistics — but **without a WebSocket broadcaster**, because it runs as
a separate process from any live API server. Replayed alerts are therefore
committed to the configured SQLite database and become visible through REST; a
separate running API process cannot receive live WebSocket deltas from this
process (its dashboard alert table refreshes on a filter change, reload or
reconnect; overview statistics refresh on their poll interval).

Provenance is always ``replay`` — there is deliberately no flag to change it.

Usage (from the repository root)::

    python scripts/replay_pcap.py <capture.pcap> [--speed N]

Exit codes:
    0  completed replay
    2  argparse usage error or invalid --speed (argparse default)
    3  packet limit reached (incomplete)
    4  truncated capture after at least one valid record (incomplete)
    5  ReplayError: missing / unreadable / oversized / invalid-header input
"""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

# Run from a clean clone without installing the package.
_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.pipeline import EventPipeline  # noqa: E402
from app.config import Settings  # noqa: E402
from app.detection import (  # noqa: E402
    DetectionEngine,
    DetectionSettings,
    PortScanDetector,
    SynFloodDetector,
)
from app.ingest.pcap_replay import ReplayError, ReplayResult, replay_pcap  # noqa: E402
from app.storage.alerts import AlertRepository  # noqa: E402
from app.storage.database import Database, connect, initialise_schema  # noqa: E402
from app.storage.stats import EventStatsRepository  # noqa: E402

_OUTCOME_EXIT_CODE = {"completed": 0, "packet_limit_reached": 3, "truncated": 4}


def _positive_finite_speed(value: str) -> float:
    """argparse type for --speed: a finite number strictly greater than zero."""
    try:
        speed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"speed must be a number (got {value!r})") from exc
    if not math.isfinite(speed) or speed <= 0:
        raise argparse.ArgumentTypeError(f"speed must be finite and > 0 (got {value!r})")
    return speed


def build_pipeline(
    settings: Settings, detection_settings: DetectionSettings
) -> tuple[EventPipeline, Database]:
    """Assemble a broadcaster-free pipeline over the configured database.

    Mirrors the backend's wiring (:func:`app.main.create_app`) minus the API and
    the WebSocket broadcaster. The caller owns the returned :class:`Database` and
    must close it.
    """
    connection = connect(settings.database_path)
    try:
        initialise_schema(connection)
    except BaseException:
        connection.close()
        raise
    database = Database(connection)
    detection = DetectionEngine(
        [
            PortScanDetector(detection_settings.to_portscan_config()),
            SynFloodDetector(detection_settings.to_synflood_config()),
        ]
    )
    repository = AlertRepository(database, max_rows=settings.alert_max_rows)
    stats = EventStatsRepository(database)
    cooldowns = {
        PortScanDetector.detector_id: detection_settings.portscan_cooldown_s,
        SynFloodDetector.detector_id: detection_settings.syn_cooldown_s,
    }
    pipeline = EventPipeline(
        detection=detection,
        alerts=AlertEngine(repository, cooldowns),
        alert_repository=repository,
        stats=stats,
        database=database,
    )
    return pipeline, database


def _report(result: ReplayResult) -> None:
    """Print a summary. The success message prints only for a completed run."""
    counts = (
        f"packets_read={result.packets_read} emitted={result.events_emitted} "
        f"dropped_unsupported={result.dropped_unsupported} "
        f"dropped_invalid={result.dropped_invalid} dropped_parse={result.dropped_parse} "
        f"alerts_created={result.alerts_created} alerts_updated={result.alerts_updated}"
    )
    if result.outcome == "completed":
        print(f"Replay complete. {counts}")
    elif result.outcome == "packet_limit_reached":
        print(f"INCOMPLETE (packet limit reached): {counts}", file=sys.stderr)
    else:  # truncated
        print(
            f"INCOMPLETE (truncated capture): {counts}; committed alerts remain.",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a PCAP into the detection pipeline.")
    parser.add_argument("pcap_path", help="Path to the capture file to replay.")
    parser.add_argument(
        "--speed",
        type=_positive_finite_speed,
        default=None,
        help="Pace delivery at this multiple of real time (finite, > 0). "
        "Omit to replay as fast as possible. Never changes detection outcomes.",
    )
    args = parser.parse_args(argv)

    settings = Settings()
    detection_settings = DetectionSettings()
    pipeline, database = build_pipeline(settings, detection_settings)
    try:
        result = replay_pcap(
            args.pcap_path,
            pipeline,
            speed=args.speed,
            batch_size=settings.replay_batch_size,
            max_packets=settings.replay_max_packets,
            max_file_bytes=settings.replay_max_file_bytes,
            max_sleep_s=settings.replay_max_sleep_s,
        )
    except ReplayError as exc:
        print(f"ERROR: {exc.reason}", file=sys.stderr)
        return 5
    finally:
        database.close()

    _report(result)
    return _OUTCOME_EXIT_CODE[result.outcome]


if __name__ == "__main__":
    raise SystemExit(main())
