"""Deduplication-key derivation for the Alert Engine.

The key format is fixed by ``docs/DETECTION_RULES.md`` §5::

    dedup_key = sha1("{detector_id}:v{major_version}:{source_type}:{src_ip or '-'}:{dst_ip}")

Only the detector's **major** version participates, so a patch release (``1.0``
→ ``1.1``) does not fork alert identity while a redesign (``2.0``) does.
``source_type`` is part of the identity, so synthetic, replay and live traffic
can never update the same alert occurrence. SHA-1 is used here as an identity /
bucketing hash, not a security primitive — collision resistance against an
adversary is not part of the design, which ``usedforsecurity=False`` states at
the call site.
"""

import hashlib

from app.models.candidate_alert import CandidateAlert


def major_version(detector_version: str) -> str:
    """Return the major component of a dotted detector version (``'1.0'`` → ``'1'``)."""
    major = detector_version.strip().split(".", 1)[0]
    if not major:
        raise ValueError(f"detector_version {detector_version!r} has no major component")
    return major


def dedup_key_for(candidate: CandidateAlert) -> str:
    """Derive the 40-character lowercase hex dedup key for a candidate."""
    identity = ":".join(
        (
            candidate.detector_id,
            f"v{major_version(candidate.detector_version)}",
            candidate.source_type,
            candidate.src_ip or "-",
            candidate.dst_ip,
        )
    )
    return hashlib.sha1(identity.encode("utf-8"), usedforsecurity=False).hexdigest()
