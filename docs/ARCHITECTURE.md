# Architecture

**Document status:** Partially implemented; this document defines the agreed Version 1 architecture in full. **Implemented through Phase 3:** the FastAPI application, configuration and health foundation; the typed domain models; the deterministic synthetic ingest source; the `DetectionEngine` with the `portscan` and `synflood` detectors; the Alert Engine (cooldown/deduplication gate); SQLite storage; the alert, statistics and authenticated ingest REST APIs; and the WebSocket broadcaster (full API contract in [API.md](API.md)). **Implemented in Phase 4:** the React frontend dashboard. **Implemented in Phase 5:** in-process PCAP replay (`ingest/pcap_replay.py`) with an unprivileged scenario generator and CLI runner, feeding the existing pipeline as `source_type="replay"` (metadata only; no HTTP endpoint). **Planned:** the Docker lab; live capture; and the AI explanation layer. See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) for current status.

**Related documents:** [PROJECT_SCOPE.md](PROJECT_SCOPE.md), [NETWORK_DESIGN.md](NETWORK_DESIGN.md), [DETECTION_RULES.md](DETECTION_RULES.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md), [TESTING_STRATEGY.md](TESTING_STRATEGY.md), [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md).

---

## 1. Architectural Principles

- **Separation of concerns.** Capture, detection, alerting, storage, API and presentation are independent modules with narrow interfaces.
- **One pipeline, many sources.** Synthetic, PCAP-replay and live-capture ingestion all normalise to the same `PacketEvent` and feed the same detection engine. Detectors never know *how* an event was produced, but they **partition their state by `source_type`**, so the three provenances never share an evidence window or update the same alert occurrence (see [DETECTION_RULES.md](DETECTION_RULES.md) §6).
- **Deterministic detection is authoritative.** The heuristic detection engine is the source of truth for alerts. The optional AI layer only *explains* alerts; it never creates, suppresses or re-grades them.
- **Testability by construction.** Detectors are pure and clock-injected, so window, expiry and cooldown logic is deterministic under test (see [TESTING_STRATEGY.md](TESTING_STRATEGY.md)).
- **Privacy by construction.** The event schema has no payload field, so payloads and credentials cannot flow through the system even by accident (see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)).

---

## 2. Component Responsibilities

| Component | Responsibility | Explicitly not responsible for |
| --- | --- | --- |
| **Ingest** (`backend/app/ingest/`) | Produce normalised `PacketEvent` objects from a source: `synthetic.py` (labelled test events), `pcap_replay.py` (parse and replay PCAPs), `live_capture.py` (the sidecar sensor). | Detection logic; storage. |
| **Detection Engine** (`backend/app/detection/`) | Hold detector instances, route each event to them, drive window/expiry via an injected clock, and emit `CandidateAlert` objects. | Persistence; transport; deciding *how* events arrive; assigning alert identity. |
| **Alert Engine** (`backend/app/alerts/`) | Turn each `CandidateAlert` into a persisted `Alert` — assign `alert_id`/`created_at`/`dedup_key`, apply the cooldown/deduplication gate, decide create-vs-update, and hand alerts to storage and the broadcaster. | Detection; raw event handling. |
| **Storage** (`backend/app/storage/`) | Persist alerts and pre-aggregated traffic statistics to SQLite; enforce retention. | Business logic; detection. |
| **REST API** (`backend/app/api/`) | Serve health, alerts, statistics and the authenticated ingest endpoint; enforce the exact browser CORS allowlist and ingest limits ([SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §4.2, §5). | Detection internals; direct DB access from routes beyond the repository layer. |
| **WebSocket Broadcaster** (`backend/app/api/`) | Push live alert deltas (`alert.created`, `alert.updated`) to connected dashboards; validate the handshake `Origin` against the allowlist. | Serving alert history (that is REST's job). |
| **Frontend** (`frontend/`) | Present statistics, live feed, alert table, charts, alert details, the traffic-source banner and the optional AI section. | Any detection or authority over alerts. |
| **Docker Lab** (`lab/`, `docker-compose.yml`) | Provide the isolated victim, generator, sensor and scenarios. | Being reachable from outside the host. |
| **AI Explanation Layer** (`backend/app/ai/`, later phase) | Turn sanitised alert metadata into plain-language explanations, with a deterministic fallback. | Detection; alert lifecycle; command execution; receiving payloads or credentials. |

---

## 3. Proposed Repository Structure

```
Network-Attack-Visualiser/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI application factory
│   │   ├── config.py          # Pydantic Settings, env-driven, documented defaults
│   │   ├── api/               # REST routes + WebSocket endpoint
│   │   ├── ingest/            # synthetic.py, pcap_replay.py, live_capture.py (sensor)
│   │   ├── detection/         # detector interface, engine, portscan.py, synflood.py
│   │   ├── alerts/            # cooldown/dedup gate, broadcasting
│   │   ├── storage/           # SQLite repository, retention pruning
│   │   ├── models/            # Pydantic schemas: PacketEvent, CandidateAlert, Alert, event_stats
│   │   └── ai/                # Phase 7 only: provider abstraction (empty until approved)
│   └── tests/
├── frontend/                  # React + Vite + Recharts dashboard
├── lab/                       # Compose lab: scenario scripts, sensor/generator assets
├── scripts/                   # generate_pcaps.py, reset_db.py (both unprivileged)
├── docs/                      # this documentation set
├── docker-compose.yml
├── .env.example
├── LICENSE
└── README.md
```

The `backend/app/ai/` directory remains empty until the AI phase is approved; no AI provider or SDK is added before then.

---

## 4. End-to-End Data Flow

All three ingestion sources converge on a single pipeline:

```
                 ┌──────────────────────────────────────────────┐
  synthetic ────►│                                              │
  PCAP replay ──►│   Ingest → PacketEvent (metadata only)       │
  live sensor ──►│                                              │
                 └───────────────────┬──────────────────────────┘
                                     │  (authenticated POST for live;
                                     │   in-process for synthetic/replay)
                                     ▼
                          ┌────────────────────┐
                          │  Detection Engine   │  injected clock
                          │  portscan, synflood │  per-key windows + expiry
                          └─────────┬──────────┘
                                    │ candidate alerts
                                    ▼
                          ┌────────────────────┐
                          │    Alert Engine     │  cooldown / dedup gate
                          │ create-vs-update    │  (see DETECTION_RULES.md)
                          └───┬────────────┬───┘
                              │            │
                     ┌────────▼───┐   ┌────▼─────────────┐
                     │  SQLite    │   │ WebSocket        │
                     │  storage   │   │ broadcaster      │
                     │  + stats   │   │ alert.created/   │
                     └────┬───────┘   │ alert.updated    │
                          │           └────┬─────────────┘
              REST (history,│                │ live deltas
               stats, detail)│               │
                          ▼                  ▼
                     ┌───────────────────────────────┐
                     │   Frontend dashboard (React)   │
                     │   REST for history, WS for live │
                     └───────────────────────────────┘
```

For the live path, the sensor shares the victim's network namespace, normalises captured frames to `PacketEvent` metadata, batches them (200 events or 0.5 s, whichever first) and POSTs them to the backend's authenticated ingest endpoint. Synthetic and replay ingestion run in-process during earlier phases and exercise the identical detection and alert path. The precise network topology, addressing and self-capture controls are specified in [NETWORK_DESIGN.md](NETWORK_DESIGN.md).

---

## 5. Key Architectural Decisions and Trade-offs

### 5.1 In-process ingestion first, sidecar sensor later
Synthetic (Phase 2) and PCAP replay (Phase 5) run inside the backend process, so the detection engine and alert pipeline can be built and fully tested before any Docker capture exists. The live sidecar sensor (Phase 6) then reuses the same ingest contract over HTTP. **Trade-off:** two delivery mechanisms (in-process and HTTP) instead of one, accepted because it lets detection maturity precede capture complexity and keeps the hardest environmental problem (live capture) last.

**Implemented (Phase 5).** `ingest/pcap_replay.py` streams a capture with Scapy `PcapReader` and hands `PacketEvent` batches to the same `EventPipeline.process_batch`; there is deliberately **no** replay HTTP endpoint. Because the CLI runner (`scripts/replay_pcap.py`) is a separate process with no broadcaster, its alerts are committed to SQLite and surface through REST but do **not** produce live WebSocket deltas in an already-open dashboard (overview statistics refresh on their poll; the alert table refreshes on a filter change, reload or reconnect). Re-replaying into the *same* engine is subject to the monotonic per-`source_type` clock (events older than the high-water mark minus the detection window are dropped as too-late); a fresh process re-detects independently.

### 5.2 WebSocket carries live deltas only; REST serves history
On page load the dashboard fetches recent alerts via REST (`GET /api/v1/alerts`); the WebSocket then streams only new `alert.created` / `alert.updated` messages. **Trade-off:** the client must reconcile a REST snapshot with a live stream, accepted to avoid a "replay storm" of historical alerts on every reconnect and to prevent duplicate keys in the UI.

### 5.3 Pre-aggregated statistics instead of raw event storage
Raw `PacketEvent` objects are never persisted individually. Traffic-timeline and protocol-distribution charts are powered by pre-aggregated `event_stats` buckets. **Trade-off:** per-packet drill-down is not available, accepted because it honours the "prefer metadata, minimise storage" principle, keeps the database small, and still fully powers the required charts (see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)).

### 5.4 SQLite as the storage engine
Alerts are low-volume and the deployment is single-node, so SQLite in WAL mode is sufficient and dependency-free. **Trade-off:** single-writer concurrency and no horizontal scale, accepted for a lab-scale tool; the repository layer isolates storage so a future engine swap is localised.

**Concurrency, as actually implemented (Phase 3).** The backend uses **one** SQLite connection guarded by one lock, with the whole ingest batch serialised as a single writer. Reads therefore **wait behind an in-flight write phase** rather than running concurrently with it — WAL's concurrent-reader benefit requires *separate reader connections*, which Phase 3 deliberately does not add (no current requirement needs them; a reader connection is the natural upgrade if dashboard polling ever contends with live ingest). WAL remains enabled for its commit behaviour and because the schema specifies it; "concurrent dashboard reads during writes" is target-architecture rationale, **not yet a realised property**. Detection work runs outside the database transaction, which shortens — but does not bound — the write window a reader may wait on.

### 5.5 Native FastAPI WebSockets
Rather than adding a separate real-time framework, V1 uses FastAPI's built-in WebSocket support. **Trade-off:** fewer turnkey features (rooms, presence), accepted because the single-channel alert stream needs none of them and the dependency surface stays minimal.

### 5.6 Clock injection and detector purity
Detectors receive `now` explicitly and perform no I/O. **Trade-off:** slightly more plumbing, richly repaid by deterministic tests and by guaranteed parity between accelerated PCAP replay and live capture.

### 5.7 Provider-abstracted, isolated AI layer
The AI explanation layer lives behind a provider abstraction in its own module and is disabled by default. **Trade-off:** an extra abstraction layer, accepted so the core application never depends on any AI provider and continues to work fully with the AI disabled (see [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md)).

---

## 6. Post-V1 Extension Points

- **Suricata ingestion.** A Suricata `eve.json` reader will normalise events behind the same `PacketEvent`/alert interfaces, so professional signature-based tooling can join the pipeline without touching detection, storage or the dashboard.
- **Deployment.** A hardened deployment path (reverse proxy, TLS, non-loopback exposure with authentication) is deferred to a post-V1 phase and is explicitly out of V1 scope.

Both are described further in [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md).
