# Alert and Event Schemas

**Document status:** Largely implemented. `PacketEvent` (§1), `CandidateAlert` (§2.0) and the `Alert` model (§2, §2.1) were implemented in Phase 2. **Implemented in Phase 3:** the SQLite tables and DDL (§4), the `event_stats` aggregation (§3), the WebSocket envelope (§5), the alert row cap from §6.1 (`ALERT_MAX_ROWS`), and the full `Alert` lifecycle (`alert_id`, `created_at`, `dedup_key`, `occurrence_count`, `last_seen`) via the Alert Engine's cooldown/deduplication gate. The REST/WebSocket contract these records are served through is specified in [API.md](API.md). **Still planned:** time-based retention and the pruning background task from §6.1 (`ALERT_RETENTION_DAYS`, `STATS_RETENTION_HOURS`) — deferred because retention days are wall-clock quantities while `created_at` is logical event time (see [API.md](API.md) §1.1); `event_stats` is therefore unbounded in Phase 3 (a recorded limitation). The AI fields (`ai_explanation`, `ai_status`) remain inert until Phase 7. See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) for current status.

**Related documents:** [ARCHITECTURE.md](ARCHITECTURE.md), [DETECTION_RULES.md](DETECTION_RULES.md), [NETWORK_DESIGN.md](NETWORK_DESIGN.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md).

---

## 1. `PacketEvent` (transport DTO)

A `PacketEvent` is the normalised, source-agnostic representation of one observed packet. Synthetic, PCAP-replay and live-capture ingestion all produce `PacketEvent` objects, so detectors never depend on how an event was produced.

**`PacketEvent` objects are never persisted individually** — they are a transport DTO consumed by the detection engine and then aggregated into `event_stats` (Section 3).

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `event_id` | `str` | UUIDv4 | Sensor/ingester-assigned identifier. |
| `ts` | `float` | epoch seconds | Capture/emit time; drives detector windows. |
| `source_type` | `str` | `"synthetic" \| "replay" \| "live"` | Provenance; drives the dashboard banner. |
| `src_ip` | `str` | IP address | Source address. |
| `src_port` | `int \| null` | 0–65535 or null | Source port; null for non-TCP/UDP. |
| `dst_ip` | `str` | IP address | Destination address. |
| `dst_port` | `int \| null` | 0–65535 or null | Destination port; null for non-TCP/UDP. |
| `protocol` | `str` | `"TCP" \| "UDP" \| "ICMP" \| "OTHER"` | Normalised L4 protocol. |
| `tcp_flags` | `str \| null` | e.g. `"S"`, `"SA"`, `"A"` | TCP flag string; null if not TCP. |
| `packet_length` | `int` | ≥ 0 | Bytes on the wire. |
| `ingest_batch_id` | `str \| null` | UUIDv4 or null | Correlates one ingest POST batch. |

### 1.1 Privacy is enforced by the type
**There is no payload field anywhere in `PacketEvent`.** The schema physically cannot carry packet payloads, so payloads and any credentials within them cannot flow through detection, storage, the API or the AI layer — even by mistake. This is the type-level realisation of the privacy boundary described in [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md). `tcp_flags` is a short control-flag string (for example `"SA"`), never data.

---

## 2.0 `CandidateAlert` (detector output — internal, never persisted)

Detectors return **`CandidateAlert`**, not the persisted `Alert`. A `CandidateAlert` is an internal DTO that carries **only** what a detector can know: it deliberately has **no** identity, timing-of-record, deduplication or AI fields, because those are the Alert Engine's responsibility. Keeping detector output free of persistence concerns is what lets detectors stay pure and clock-injected (see [DETECTION_RULES.md](DETECTION_RULES.md) §2).

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `detector_id` | `str` | e.g. `"portscan"` | Emitting detector. |
| `detector_version` | `str` | e.g. `"1.0"` | Detector version. |
| `category` | `str` | e.g. `"reconnaissance"`, `"dos"` | Alert category. |
| `severity` | `str` | `"low" \| "medium" \| "high" \| "critical"` | Severity band. |
| `confidence` | `float` | `0.0`–`0.95` | Heuristic strength; never 1.0. |
| `src_ip` | `str \| null` | IP or null | Source; null for destination-keyed detectors. |
| `dst_ip` | `str` | IP address | Destination host. |
| `source_type` | `str` | `"synthetic" \| "replay" \| "live"` | Provenance of the triggering traffic (part of the detector-state key; see [DETECTION_RULES.md](DETECTION_RULES.md) §6). |
| `evidence` | `JSON` | object | Detector-specific evidence (§2.1). |
| `threshold_snapshot` | `JSON` | object | Threshold values active when the candidate fired. |
| `window_start` | `float` | epoch seconds | Start of the evidence window. |
| `window_end` | `float` | epoch seconds | End of the evidence window. |

**What the Alert Engine adds** when it turns a `CandidateAlert` into a persisted `Alert`: `alert_id`, `created_at`, `dedup_key`, `occurrence_count`, `last_seen`, the AI fields (`ai_explanation`, `ai_status`), and all deduplication/cooldown lifecycle state (create-vs-update; see [DETECTION_RULES.md](DETECTION_RULES.md) §5). A detector never sets or sees these.

---

## 2. `Alert` (persisted)

An `Alert` is produced from a detector's `CandidateAlert` (§2.0) and finalised by the Alert Engine's cooldown/deduplication gate (see [DETECTION_RULES.md](DETECTION_RULES.md)). The Alert Engine copies the candidate's detector fields through and adds the identity, timing, dedup and AI fields below.

| Field | Type | Constraints | Description |
| --- | --- | --- | --- |
| `alert_id` | `str` | UUIDv4, primary key | Unique alert identifier. |
| `created_at` | `float` | epoch seconds | When the alert row was first created. |
| `detector_id` | `str` | e.g. `"portscan"`, `"synflood"` | Emitting detector. |
| `detector_version` | `str` | e.g. `"1.0"` | Detector version. |
| `category` | `str` | e.g. `"reconnaissance"`, `"dos"` | Alert category. |
| `severity` | `str` | `"low" \| "medium" \| "high" \| "critical"` | Severity band (see [DETECTION_RULES.md](DETECTION_RULES.md)). |
| `confidence` | `float` | `0.0`–`0.95` | Heuristic strength; never 1.0. |
| `src_ip` | `str \| null` | IP or null | Source; null for destination-keyed detectors (e.g. `synflood`). |
| `dst_ip` | `str` | IP address | Destination host. |
| `window_start` | `float` | epoch seconds | Start of the evidence window. |
| `window_end` | `float` | epoch seconds | End of the evidence window (extended on update). |
| `evidence` | `JSON` | object | Detector-specific evidence (Section 2.1). |
| `threshold_snapshot` | `JSON` | object | Threshold values active when the alert fired (reproducibility). |
| `dedup_key` | `str` | indexed, **non-unique** | Identity key for cooldown/dedup; **includes `source_type`** so provenances never merge (see [DETECTION_RULES.md](DETECTION_RULES.md) §5–§6). |
| `source_type` | `str` | `"synthetic" \| "replay" \| "live"` | Provenance of the traffic that triggered it. |
| `occurrence_count` | `int` | ≥ 1, default 1 | Times this alert was reinforced within its cooldown. |
| `last_seen` | `float` | epoch seconds | Most recent reinforcement time. |
| `ai_explanation` | `str \| null` | null until generated | AI or fallback explanation text (see [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md)). |
| `ai_status` | `str` | `"none" \| "generated" \| "fallback" \| "error"`, default `"none"` | AI explanation lifecycle state. |

### 2.1 Evidence contents
`evidence` is a JSON object whose keys depend on the detector, matching the evidence fields specified in [DETECTION_RULES.md](DETECTION_RULES.md):

- **portscan:** `distinct_port_count`, `sampled_ports` (≤ 20), `syn_count`, `window_start`, `window_end`, `duration_s`.
- **synflood:** `syn_count`, `synack_count`, `completed_handshakes`, `completion_ratio`, `distinct_src_count`, `syn_rate_per_s`, `window_start`, `window_end`.

`threshold_snapshot` records the relevant thresholds (for example `PORTSCAN_MIN_PORTS`, `PORTSCAN_WINDOW_S`) so the alert remains fully interpretable even if configuration changes later.

**Finite JSON only.** `evidence` and `threshold_snapshot` accept strictly JSON-serialisable content that is **free of non-finite numbers at every nesting depth** — `NaN` and `±Infinity` are rejected on both `CandidateAlert` and `Alert`, not coerced. JSON has no representation for them, so the permissive behaviour is to serialise them to `null`: an alert would appear well-formed while its evidence had silently become nothing. For a record whose purpose is to remain interpretable after the fact, refusing the value is the only honest option.

---

## 3. `event_stats` (pre-aggregated statistics)

Raw events are not stored. To power the traffic-timeline and protocol-distribution charts, ingestion maintains pre-aggregated **one-second buckets**:

| Field | Type | Description |
| --- | --- | --- |
| `bucket_ts` | `REAL` | Bucket start (epoch seconds, truncated to the second). |
| `protocol` | `TEXT` | `TCP` / `UDP` / `ICMP` / `OTHER`. |
| `source_type` | `TEXT` | `synthetic` / `replay` / `live`. |
| `packet_count` | `INTEGER` | Packets in the bucket. |
| `byte_count` | `INTEGER` | Bytes in the bucket. |

This keeps the database small and honours the "prefer metadata, minimise storage" principle while still fully powering the required charts. Per-packet drill-down is intentionally not offered (see [PROJECT_SCOPE.md](PROJECT_SCOPE.md)).

---

## 4. SQLite Schema (DDL)

```sql
PRAGMA journal_mode = WAL;   -- durability/commit behaviour now; reader concurrency
                             -- requires separate reader connections and is NOT
                             -- realised by Phase 3's single shared connection
                             -- (see ARCHITECTURE.md §5.4). File databases only:
                             -- SQLite silently ignores WAL for ':memory:'.

CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT    PRIMARY KEY,
    created_at          REAL    NOT NULL,
    detector_id         TEXT    NOT NULL,
    detector_version    TEXT    NOT NULL,
    category            TEXT    NOT NULL,
    severity            TEXT    NOT NULL,
    confidence          REAL    NOT NULL,
    src_ip              TEXT,
    dst_ip              TEXT    NOT NULL,
    window_start        REAL    NOT NULL,
    window_end          REAL    NOT NULL,
    evidence            TEXT    NOT NULL,   -- JSON
    threshold_snapshot  TEXT    NOT NULL,   -- JSON
    dedup_key           TEXT    NOT NULL,
    source_type         TEXT    NOT NULL,
    occurrence_count    INTEGER NOT NULL DEFAULT 1,
    last_seen           REAL    NOT NULL,
    ai_explanation      TEXT,
    ai_status           TEXT    NOT NULL DEFAULT 'none'
);

-- Non-unique: dedup_key must NEVER permanently block future alerts for the same hosts.
CREATE INDEX IF NOT EXISTS idx_alerts_dedup     ON alerts (dedup_key, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_detector  ON alerts (detector_id, severity);

CREATE TABLE IF NOT EXISTS event_stats (
    bucket_ts     REAL    NOT NULL,
    protocol      TEXT    NOT NULL,
    source_type   TEXT    NOT NULL,
    packet_count  INTEGER NOT NULL,
    byte_count    INTEGER NOT NULL,
    PRIMARY KEY (bucket_ts, protocol, source_type)
);
```

`idx_alerts_dedup` is deliberately **non-unique**: it accelerates "most recent alert for this key" for the cooldown gate, but never enforces uniqueness, so a source/destination pair can always raise future alerts after its cooldown elapses (see [DETECTION_RULES.md](DETECTION_RULES.md)).

---

## 5. WebSocket Message Envelope

The WebSocket channel (`WS /api/v1/ws/alerts`) carries **live deltas only**. Alert history is fetched over REST on page load; the socket then streams changes:

```json
{ "type": "alert.created", "alert": { /* full Alert object */ } }
{ "type": "alert.updated", "alert": { /* full Alert object, occurrence_count/last_seen/window_end updated */ } }
```

- `alert.created` — a new alert row was inserted (first trigger, or first trigger after a cooldown elapsed).
- `alert.updated` — an existing alert was reinforced within its cooldown window (`occurrence_count` incremented; severity may have escalated upward).

The client reconciles these deltas against the REST snapshot it loaded, keyed by `alert_id`. No historical alerts are replayed over the socket, which avoids reconnect "replay storms" and duplicate keys in the UI.

---

## 6. Data Retention and Privacy Boundaries

### 6.1 Retention
| Data | Retention | Variable |
| --- | --- | --- |
| Alerts | 7 days, or a rolling cap of 10 000 rows, whichever prunes first | `ALERT_RETENTION_DAYS=7`, `ALERT_MAX_ROWS=10000` |
| `event_stats` buckets | 24 hours | `STATS_RETENTION_HOURS=24` |

A background task prunes on these limits. The database is **ephemeral lab data**: it is gitignored (the repository `.gitignore` blocks `*.db`, `*.sqlite*`), can be deleted freely, and a `scripts/reset_db.py` helper recreates it.

### 6.2 Privacy boundaries
What the system **never** stores or logs, at any layer:

- Packet payloads (there is no payload field to begin with).
- Passwords, authentication tokens, cookies, or any credentials.
- Full packet captures inside the database.

Only the metadata fields defined above are retained. The AI layer receives an even narrower, sanitised subset (see [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md)).
