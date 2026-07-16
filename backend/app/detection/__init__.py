"""The detection engine and heuristic detectors.

Phase 2 provides the clock-injected detector interface
(:class:`~app.detection.base.Detector`), the :class:`~app.detection.engine.DetectionEngine`,
and the :class:`~app.detection.portscan.PortScanDetector` and
:class:`~app.detection.synflood.SynFloodDetector` detectors, driven by typed
thresholds from :mod:`app.detection.config`. Detectors are pure and return
:class:`~app.models.candidate_alert.CandidateAlert` objects; persistence,
deduplication and cooldown belong to the later Alert Engine.
"""

from app.detection.base import Detector, SeverityLatch
from app.detection.config import DetectionSettings, PortScanConfig, SynFloodConfig
from app.detection.engine import DetectionEngine
from app.detection.portscan import PortScanDetector
from app.detection.synflood import SynFloodDetector

__all__ = [
    "DetectionEngine",
    "DetectionSettings",
    "Detector",
    "PortScanConfig",
    "PortScanDetector",
    "SeverityLatch",
    "SynFloodConfig",
    "SynFloodDetector",
]
