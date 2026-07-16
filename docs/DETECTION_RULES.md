# Detection Rules

**Document status:** Partially implemented. **Implemented in Phase 2:** the detector interface contract (§2), including the source-aware `expire(source_type, now)` contract; the event-time, out-of-order and too-late policy (§2.1); the `portscan` detector (§3); the `synflood` detector (§4); and the detector configuration variables (§8). The detector overlap policy (§6) is **already reflected at the `CandidateAlert` output level**: `DetectionEngine` returns the candidates of every detector independently, with no cross-detector deduplication. The scenario mapping (§7) is **already exercised in-process** through `DetectionEngine` against the synthetic scenarios (normal → no candidates; port scan → `portscan`; SYN burst → `synflood`). **Planned for Phase 3:** converting `CandidateAlert` objects into persisted `Alert` records, the Alert Engine lifecycle and its cooldown/deduplication gate (§5), and broadcasting alert updates; the `*_COOLDOWN_S` values in §8 are loaded and validated but not yet consumed by anything. See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) for current status.

**Related documents:** [PROJECT_SCOPE.md](PROJECT_SCOPE.md), [ARCHITECTURE.md](ARCHITECTURE.md), [NETWORK_DESIGN.md](NETWORK_DESIGN.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [TESTING_STRATEGY.md](TESTING_STRATEGY.md).

---

## 1. Laboratory-Defaults Disclaimer

> **All threshold, window, cooldown and expiry values in this document are *initial laboratory defaults*.** They are chosen to make the demonstration scenarios trigger cleanly in an isolated lab. They are **configurable** (every value maps to an environment variable) and are **not** universal security standards, tuned production values, or guarantees. Real deployments would require tuning against a baseline.

Consistent with project policy, detection is **heuristic**. No detector claims an attack with certainty. Each alert carries a `confidence` value that expresses **heuristic strength**, not a calibrated probability, and is capped at **0.95** — never 1.0.

---

## 2. Detector Interface Contract

Every detector implements a single, small interface:

```python
class Detector(Protocol):
    detector_id: str        # e.g. "portscan"
    detector_version: str   # e.g. "1.0"

    def update(self, event: PacketEvent, now: float) -> list[CandidateAlert]:
        """Consume one event at logical time `now`; return zero or more CandidateAlerts."""

    def expire(self, source_type: SourceType, now: float) -> None:
        """Prune `source_type` state whose window/TTL has elapsed as of `now`."""
```

**Why `expire` names a `source_type`.** Detector state is partitioned by `source_type` (§2.1, §6) and **each partition runs on its own logical clock** — synthetic, replay and live timelines are unrelated and can diverge by years. A single global `expire(now)` therefore has no correct meaning: applied to every partition it would let one provenance's clock age out another's state (a live event would instantly expire a replay's evidence window), and ignoring `now` to avoid that would leave the parameter a lie. Naming the partition the supplied `now` belongs to is what lets the logical time actually be honoured **and** keeps provenances isolated. A detector advances and sweeps only the named partition; an unknown `source_type` is a no-op.

Detectors return **`CandidateAlert`** objects, **not** the persisted `Alert` model. A `CandidateAlert` carries only detector-produced information (detector ID/version, category, severity, confidence, source/destination, evidence, `threshold_snapshot`, `source_type` and evidence-window times). The Alert Engine is what turns a `CandidateAlert` into a persisted `Alert`, assigning `alert_id`, `created_at`, `dedup_key`, `occurrence_count`, `last_seen`, the AI fields and the persistence lifecycle. The exact `CandidateAlert` fields are defined in [ALERT_SCHEMA.md](ALERT_SCHEMA.md) §2.0.

Design rules and their rationale:

- **Clock injected, never read.** Detectors receive `now` as a parameter and never call `time.time()`. This makes detector window and expiry behaviour deterministic under test, and because event timestamps are preserved end-to-end, accelerated PCAP replay and live processing produce equivalent detector results (see [TESTING_STRATEGY.md](TESTING_STRATEGY.md) and §2.1 below). Cooldown behaviour is not a detector concern: the Phase 3 Alert Engine must apply this same injected logical-time principle when it implements the cooldown gate (§5). An injected clock is only honest if it is actually honoured: `expire(source_type, now)` advances that partition's logical time to `now` rather than discarding it.
- **Pure, no I/O.** Detectors do not touch the database, the network or the clock. They transform (event, state) into candidate alerts. Persistence and broadcasting are the Alert Engine's job.
- **Per-key sliding windows.** Each detector keys events (see each spec) and maintains a bounded sliding window of recent timestamps/facts per key. **Every detector-state key includes `source_type`** so synthetic, replay and live traffic can never share an evidence window (§6, [ARCHITECTURE.md](ARCHITECTURE.md)).
- **Periodic state sweep.** The engine calls `expire(event.source_type, now)` regularly so idle keys free their state after a configured TTL, bounding memory.
- **No state without cause.** A packet a detector cannot act on must leave **no trace**: it may not create a state key, window entry or pending entry, and may not refresh an existing key's idle TTL. Otherwise ignored traffic would both leak memory and keep dead keys alive forever, defeating the sweep above. Each detector therefore classifies a packet and applies its **packet-specific age gate before** touching any state, and refreshes a key's last-activity time only when the packet actually creates, progresses, completes or removes state (advancing it to `max(existing, event.ts)`, so an out-of-order packet never rewinds it).

The candidate alerts a detector returns are passed to the Alert Engine, which applies the cooldown/deduplication gate in Section 5 before anything is stored or broadcast.

### 2.1 Event-time semantics (one canonical logical clock)
Detector windows operate on **one canonical logical event time** — the `now` passed to `update`/`expire` — which the Detection Engine derives from `PacketEvent.ts` (the event's capture/emit time), **never** from wall-clock time. This single definition of "now" is what makes the three ingestion sources interchangeable:

- **Synthetic** (Phase 2): `ts` is assigned deterministically by the generator.
- **PCAP replay** (Phase 5): `ts` is the **packet's capture timestamp preserved from the PCAP**. Replay may *accelerate wall-clock delivery* (shortening or removing the real-time sleeps between packets), but it **must not** compress the detection windows or alter which alerts fire: detectors only ever see the preserved capture timestamps, so an accelerated replay and a real-time replay of the same PCAP produce **identical** alerts. See [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §11.
- **Live** (Phase 6): `ts` is the sensor's capture time.

**Monotonic logical time for expiry.** The engine advances a per-source-type logical high-water mark equal to the greatest `ts` seen and drives `expire(event.source_type, now)` from it, so logical time never runs backwards even when packets arrive slightly out of order — and so each provenance is only ever swept against its own timeline.

**Out-of-order and unreasonable timestamps.**
- *Mild reordering* (an event whose `ts` is at or after the current window start but below the high-water mark) is still placed in its correct window by timestamp; it does not rewind the high-water mark, so it cannot prematurely trigger `expire`.
- *Too-late events* (`ts` older than the current sliding-window start) are **dropped** and counted in a `dropped_late` metric rather than mutating a window that has already closed.
- *Unreasonable timestamps* — non-finite (`NaN`/`inf`), or skewed beyond a configurable bound from the ingest reference time (live path: `MAX_CLOCK_SKEW_S`, see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §5.1) — are **rejected before detection** and never reach a detector window.

---

## 3. Detector: `portscan` v1.0

| Attribute | Value |
| --- | --- |
| Detector ID / version | `portscan` / `1.0` |
| Category | `reconnaissance` |
| Key | `(source_type, src_ip, dst_ip)` |

**Detection objective.** Detect TCP port enumeration — a single source probing many distinct ports on a single destination host.

**Detection logic.** For each `(source_type, src_ip, dst_ip)` key, count the set of **distinct TCP destination ports** observed on **SYN-only** packets (TCP flags `SYN=1, ACK=0`) within a sliding window. Counting SYN-only packets targets connection *initiation* and avoids counting backhaul of established sessions. Including `source_type` in the key keeps synthetic, replay and live traffic in separate evidence windows (§6).

**Observation window.** `PORTSCAN_WINDOW_S` (default **10 s**), sliding.

**Trigger.** `distinct_ports >= PORTSCAN_MIN_PORTS` within the window (default **15**).

**Thresholds (defaults).**

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORTSCAN_WINDOW_S` | `10` | Sliding window length (seconds). |
| `PORTSCAN_MIN_PORTS` | `15` | Distinct ports that trigger an alert. |
| `PORTSCAN_CRITICAL_PORTS` | `100` | Fan-out at/above which severity is critical. |
| `PORTSCAN_STATE_TTL_S` | `60` | Idle-key state expiry. |
| `PORTSCAN_COOLDOWN_S` | `60` | Alert cooldown (Section 5). |

Configuration validation: `PORTSCAN_CRITICAL_PORTS` must be greater than `2 × PORTSCAN_MIN_PORTS` so the severity bands below are well-formed.

**Severity — exact boundaries** (with `N = PORTSCAN_MIN_PORTS = 15`, `PORTSCAN_CRITICAL_PORTS = 100`):

| Severity | Condition (distinct ports `p`) | With defaults |
| --- | --- | --- |
| medium | `N ≤ p < 2N` | 15–29 |
| high | `2N ≤ p < PORTSCAN_CRITICAL_PORTS` | 30–99 |
| critical | `p ≥ PORTSCAN_CRITICAL_PORTS` | ≥ 100 |

**Confidence.** `min(0.95, 0.60 + 0.35 × (p − N) / (PORTSCAN_CRITICAL_PORTS − N))` — rises from the trigger point towards the cap as fan-out approaches critical.

**Evidence fields** (stored on the alert; see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)): `distinct_port_count`, `sampled_ports` (a representative sample, capped at ≤ 20), `syn_count`, `window_start`, `window_end`, `duration_s`.

**State expiry.** A `(source_type, src_ip, dst_ip)` key with no new SYN for `PORTSCAN_STATE_TTL_S` is dropped by `expire(source_type, now)`.

**False positives.**
- Monitoring / health-check systems that probe many ports.
- Authorised vulnerability scanners.
- Clients legitimately opening many parallel connections to different ports.
- Load balancers and service-discovery bursts.

**Limitations.**
- Slow ("low-and-slow") scans that stay under the window evade detection.
- Distributed scans from many sources are not correlated (single-source key).
- UDP scanning is out of V1 scope.
- Visibility is victim-centric (see [NETWORK_DESIGN.md](NETWORK_DESIGN.md)).

---

## 4. Detector: `synflood` v1.0

| Attribute | Value |
| --- | --- |
| Detector ID / version | `synflood` / `1.0` |
| Category | `dos` |
| Key | `(source_type, dst_ip)` (destination-centric — floods target a host) |

**Detection objective.** Detect SYN floods and half-open connection abuse against the victim: a high rate of connection initiations with a low proportion of completed handshakes.

**Detection logic.** Within a sliding window, count SYNs toward the key host and the proportion of those that complete a handshake, using the state machine below. Alert when the SYN volume is high **and** the completion ratio is low. Two conditions together prevent flagging a merely busy-but-healthy server.

### 4.1 Handshake-matching state machine
Within a single `(source_type, dst_ip)` key, state is tracked as **pending entries** keyed by the connection 4-tuple `(src_ip, src_port, dst_ip, dst_port)`. Each pending entry records a boolean **`syn_observed`** — whether *this detector actually saw the initiating SYN* — and, when it did, the `syn_ts` of that SYN. This flag is the crux of correct completion accounting: **only entries with `syn_observed == True` are ever counted in the denominator, and only their completions are ever counted in the numerator.** An entry synthesised from a SYN-ACK we never saw a SYN for (`syn_observed == False`) is tracked for matching purposes but can contribute to **neither** `syn_count` **nor** `completed_handshakes`.

For traffic involving the key host:

| Packet (relative to key host) | Rule |
| --- | --- |
| **SYN** (`SYN=1, ACK=0`) toward key host | **Age gate:** if `ts < now − SYN_WINDOW_S` the SYN can never join a cohort → ignore it entirely, creating **no** key, pending entry or cohort attempt. Otherwise: if **no** pending entry exists for the 4-tuple, create one with `syn_observed = True`, record `syn_ts`, register the SYN in the window cohort (this is what increments `syn_count`), and set state `SYN_SEEN`. If a pending entry **already** exists with `syn_observed == True`, this is a **retransmitted SYN** → refresh only; do **not** double-count. If a pending entry exists with `syn_observed == False` (it was born from an orphan SYN-ACK), now that a real SYN is observed, set `syn_observed = True`, record `syn_ts`, and register it in the cohort (so it *becomes* eligible for the numerator/denominator). |
| **SYN-ACK** (`SYN=1, ACK=1`) from key host, matching the reversed 4-tuple | **Age gate:** if `ts < now − HANDSHAKE_TTL_S` the handshake is already dead → ignore entirely, creating no key or pending entry. Otherwise **progression and evidence are accounted separately** (see §4.2): add `ts` to the `synack_count` evidence window **only if** `ts ≥ now − SYN_WINDOW_S`, so `synack_count` and the SYN cohort always describe the *same* window; an older-but-still-matchable SYN-ACK may progress state without becoming evidence. Then, if a pending entry exists, move it to `SYN_ACK_SEEN`, leaving `syn_observed` unchanged. If **no** pending entry exists (the SYN was missed), create the entry in `SYN_ACK_SEEN` with `syn_observed = False` and **do not** register it in the cohort — `syn_count` is untouched. |
| **Final ACK** (`ACK=1, SYN=0, RST=0, FIN=0`) toward key host, matching a pending entry | **Age gate:** if `ts < now − HANDSHAKE_TTL_S`, ignore entirely. Otherwise remove the entry. Count one `completed_handshake` **only if `syn_observed == True`**, attributing the completion to that entry's `syn_ts` cohort (so the numerator can never reference an attempt absent from the denominator). If `syn_observed == False` (orphan SYN-ACK origin), remove the entry **without** counting any completion — it was never in the denominator, so it must never enter the numerator. This still tolerates a lost/out-of-order SYN-ACK **as long as the SYN itself was observed**. |
| **ACK** with no matching pending entry | Ignore (established-flow traffic): create **no** key state and do **not** refresh the key's idle TTL. |
| **RST** from key host matching an entry | **Age gate:** if `ts < now − HANDSHAKE_TTL_S`, ignore entirely. Otherwise remove the entry **without** counting a completion. An RST matching **no** pending entry is ignored and, like a bare ACK, creates no key state and does not refresh the TTL. |
| Pending entry with no progress for `HANDSHAKE_TTL_S` | Expire it (deemed a half-open / incomplete handshake). Expiry never adds a completion. |

This is an *approximate* state machine, not a full TCP implementation; the approximations (retransmission de-duplication, observed-SYN-gated completion, out-of-order final ACK) are chosen to be robust to normal packet loss and reordering in the lab **while keeping the completion ratio well-formed**.

### 4.2 Window cohort, ratio and trigger
The denominator and numerator must refer to **the same cohort of attempts**. The cohort is defined by **SYN observation time**: an attempt belongs to the current window iff its observed `syn_ts` lies in the sliding `SYN_WINDOW_S` window `[now − SYN_WINDOW_S, now]`. Over that window:

- `syn_count` = number of cohort attempts (entries registered by an observed SYN whose `syn_ts` is in-window). Retransmissions and orphan SYN-ACKs are excluded by §4.1.
- `completed_handshakes` = number of **those same** cohort attempts (`syn_ts` in-window, `syn_observed == True`) that reached a final ACK. A completion is attributed to its attempt's `syn_ts`, so it enters the numerator **only while** its SYN remains in-window.
- `synack_count` = SYN-ACKs whose `ts` lies in the **same** `SYN_WINDOW_S` window. This is why §4.1 gates SYN-ACK *evidence* on `SYN_WINDOW_S` while allowing *progression* for the longer `HANDSHAKE_TTL_S`: the two horizons answer different questions. `HANDSHAKE_TTL_S` asks "could this packet still belong to a handshake we are tracking?"; `SYN_WINDOW_S` asks "does this packet describe the burst we are reporting?". Conflating them would let a SYN-ACK from outside the reported window inflate the evidence of a burst it was never part of.

```
completion_ratio = completed_handshakes / syn_count      (undefined, and no trigger, when syn_count == 0)
```

Because `completed_handshakes` counts a strict **subset** of the attempts counted by `syn_count` (every completion maps to exactly one in-window observed SYN, and orphan SYN-ACK completions are excluded by construction), the ratio is always well-formed:

```
0.0 <= completion_ratio <= 1.0
```

**Trigger.** `syn_count >= SYN_MIN_COUNT` **AND** `completion_ratio < SYN_MAX_COMPLETION_RATIO`.

**Thresholds (defaults).**

| Variable | Default | Meaning |
| --- | --- | --- |
| `SYN_WINDOW_S` | `5` | Sliding window length (seconds). |
| `SYN_MIN_COUNT` | `100` | SYNs in-window required to consider a flood. |
| `SYN_MAX_COMPLETION_RATIO` | `0.2` | Completion ratio below which traffic is suspicious. |
| `HANDSHAKE_TTL_S` | `10` | Pending-entry expiry (half-open timeout). |
| `SYN_STATE_TTL_S` | `30` | Idle-key state expiry. |
| `SYN_COOLDOWN_S` | `60` | Alert cooldown (Section 5). |

**Severity — exact boundaries** (with defaults `SYN_MIN_COUNT = 100`, `SYN_MAX_COMPLETION_RATIO = 0.2`):

| Severity | Condition | With defaults |
| --- | --- | --- |
| medium | `SYN_MIN_COUNT ≤ syn_count < 2 × SYN_MIN_COUNT` and `ratio < SYN_MAX_COMPLETION_RATIO` | 100 ≤ syn < 200, ratio < 0.2 |
| high | `syn_count ≥ 2 × SYN_MIN_COUNT` **or** `ratio < SYN_MAX_COMPLETION_RATIO / 2` | syn ≥ 200 **or** ratio < 0.1 |
| critical | `syn_count ≥ 5 × SYN_MIN_COUNT` **and** `ratio < SYN_MAX_COMPLETION_RATIO / 4` | syn ≥ 500 **and** ratio < 0.05 |

Severity is evaluated from the most severe band downward (critical, then high, then medium).

**Confidence.** `min(0.95, 0.60 + 0.35 × (1 − completion_ratio / SYN_MAX_COMPLETION_RATIO))` — rises as the completion ratio falls further below the threshold.

**Evidence fields:** `syn_count`, `synack_count`, `completed_handshakes`, `completion_ratio`, `distinct_src_count`, `syn_rate_per_s`, `window_start`, `window_end`.

**State expiry.** Pending entries expire after `HANDSHAKE_TTL_S`; a key host idle for `SYN_STATE_TTL_S` is dropped entirely. "Idle" means no packet that *affected* this key's state: per §2, traffic the detector ignores (an out-of-window SYN, an age-gated handshake packet, a bare ACK or an unmatched RST) does not count as activity and cannot hold a dead key open.

**False positives.**
- Legitimate traffic bursts (flash crowds).
- Aggressive connection pooling by clients.
- Asymmetric capture that hides SYN-ACKs and lowers the observed completion ratio — largely mitigated here because namespace capture (see [NETWORK_DESIGN.md](NETWORK_DESIGN.md)) sees both directions to the victim.
- Frequent health-check probes.

**Limitations.**
- The handshake tracker is approximate, not a full TCP state machine.
- Spoofed-source floods inflate `distinct_src_count`; that is expected and is surfaced as evidence, not corrected.
- When a burst is both a scan and a flood, this detector and `portscan` may both fire (Section 6).

---

## 5. Alert Deduplication and Cooldown Semantics

Deduplication controls alert **noise** without ever permanently silencing a source/destination pair. This is a required, fully-defined behaviour.

**Dedup key.**

```
dedup_key = sha1("{detector_id}:v{major_version}:{source_type}:{src_ip or '-'}:{dst_ip}")
```

For `synflood`, which is destination-keyed, `src_ip` is absent and the `-` placeholder is used. **`source_type` is part of the dedup identity** (matching the detector-state keys in §3–§4): synthetic, replay and live traffic therefore never update the same alert occurrence, so a demonstration replay can never be folded into — or silence — a live alert (§6).

**The dedup key is an *identity* key, not a database unique constraint.** There is **no permanent unique constraint** on `dedup_key`. A permanent unique key would be wrong: it would mean a source/destination pair that triggered once could *never* raise a future alert, permanently blinding the system to that pair. That must not happen.

**In-memory gate state.** The Alert Engine keeps, per `dedup_key`, `{ latest_alert_id, last_fired_at }`.

**Within the cooldown window** (`now − last_fired_at < COOLDOWN`): the new trigger **updates** the existing (most recent) alert row for that key rather than inserting a new one:

- `occurrence_count += 1`
- `last_seen = now`
- `window_end` extended to the current window end
- evidence refreshed to the latest values
- severity may only **escalate upward** on update (never auto-lowered), to avoid flapping
- the updated alert is re-broadcast on the WebSocket as **`alert.updated`**

**After the cooldown elapses** (`now − last_fired_at ≥ COOLDOWN`): the next trigger **creates a new** alert row (new `alert_id`, `occurrence_count = 1`, `last_fired_at = now`) and is broadcast as **`alert.created`**.

**Database.** A **non-unique** index on `(dedup_key, created_at)` supports "find the most recent alert for this key" efficiently. See the DDL in [ALERT_SCHEMA.md](ALERT_SCHEMA.md).

---

## 6. Detector Overlap Policy

`portscan` and `synflood` can both fire on the same burst of SYN traffic (a large SYN flood also looks like touching many ports; a fast scan also looks like many half-open connections). **This is intentional.** There is **no cross-detector deduplication** in V1: each detector reports independently, and an operator seeing both alerts is seeing a truthful account of two heuristics agreeing. Cross-detector correlation is future work (see [PROJECT_SCOPE.md](PROJECT_SCOPE.md)).

---

## 7. Detector-to-Scenario Mapping

The lab scenarios (see [NETWORK_DESIGN.md](NETWORK_DESIGN.md) and [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md)) exercise the detectors as follows, giving reviewers a reproducible way to see each alert:

| Scenario | Expected result |
| --- | --- |
| Normal traffic | No alerts. |
| Port scan | `portscan` alert (severity by fan-out). |
| SYN burst | `synflood` alert; may also raise `portscan` if the burst spans many ports (Section 6). |

---

## 8. Configuration Variable Summary

All values are initial laboratory defaults and are configurable via environment variables.

| Variable | Default | Detector | Purpose |
| --- | --- | --- | --- |
| `PORTSCAN_WINDOW_S` | `10` | portscan | Sliding window (s). |
| `PORTSCAN_MIN_PORTS` | `15` | portscan | Distinct ports to trigger. |
| `PORTSCAN_CRITICAL_PORTS` | `100` | portscan | Critical-severity fan-out. |
| `PORTSCAN_STATE_TTL_S` | `60` | portscan | Idle-key state expiry (s). |
| `PORTSCAN_COOLDOWN_S` | `60` | portscan | Alert cooldown (s). |
| `SYN_WINDOW_S` | `5` | synflood | Sliding window (s). |
| `SYN_MIN_COUNT` | `100` | synflood | SYNs to consider a flood. |
| `SYN_MAX_COMPLETION_RATIO` | `0.2` | synflood | Suspicious completion ceiling. |
| `HANDSHAKE_TTL_S` | `10` | synflood | Pending-entry (half-open) expiry (s). |
| `SYN_STATE_TTL_S` | `30` | synflood | Idle-key state expiry (s). |
| `SYN_COOLDOWN_S` | `60` | synflood | Alert cooldown (s). |

**Validation.** Configuration is untrusted input. Every window, TTL, cooldown and ratio above must be **finite and positive**: `NaN` and `±Infinity` are rejected on load, never clamped or accepted. This is not pedantry — `float("inf")` parses happily from an environment variable, and an infinite window or TTL would silently disable expiry (state would grow without bound), while `NaN` makes every window comparison false and would silently disable detection itself. A detection engine that fails loudly at startup is strictly better than one that quietly stops detecting. The same rule applies to the engine's derived acceptance horizon (§2.1).

Every alert stores a `threshold_snapshot` of the values active when it fired, so an alert remains interpretable even if configuration changes later (see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)).
