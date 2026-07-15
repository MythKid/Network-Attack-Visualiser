# Development Phases

**Document status:** Phase 0 design. This document defines the agreed Version 1 delivery plan and the acceptance criteria for each phase.

**Related documents:** [PROJECT_SCOPE.md](PROJECT_SCOPE.md), [ARCHITECTURE.md](ARCHITECTURE.md), [NETWORK_DESIGN.md](NETWORK_DESIGN.md), [DETECTION_RULES.md](DETECTION_RULES.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [TESTING_STRATEGY.md](TESTING_STRATEGY.md), [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md), [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md).

---

## Working Rule

Development proceeds **one approved phase at a time**. No phase begins without explicit approval. Nothing is committed or pushed without explicit instruction. Each phase has concrete, runnable acceptance criteria so "done" is demonstrable rather than asserted.

---

## Phase Overview

| Phase | Title | Status |
| --- | --- | --- |
| 0 | Design documentation | Complete |
| 0.5 | Tooling and CI baseline | Complete |
| 1 | Backend skeleton | Planned (next) |
| 2 | Detection engine + synthetic events | Planned |
| 3 | Alert pipeline (storage, REST, WebSocket) | Planned |
| 4 | Frontend dashboard | Planned |
| 5 | PCAP replay + Scapy hardening | Planned |
| 6 | Docker lab + live sidecar capture | Planned |
| 7 | AI explanation layer | Planned |
| 8 | Hardening and polish | Planned |
| Post-V1 | Suricata integration; deployment | Future |

---

## Phase 0 — Design Documentation (this phase)

**Scope.** Author the full design documentation set under `docs/` plus the README, specifying V1 before any code is written.

**Deliverables.** The ten documents in this set and a rewritten `README.md`.

**Acceptance criteria.**
- All ten documents and the README exist and are complete (no stubs or TODOs).
- Values are internally consistent across documents.
- Nothing is described as implemented.
- No application code, dependencies, containers or services created.

---

## Phase 0.5 — Tooling and CI Baseline (Approved)

**Scope.** Establish the quality and continuous-integration baseline before substantial application code exists, and resolve the licence decision. Configuration is kept **proportionate to current project maturity** — enough to enforce good habits, deliberately **not** so strict that it obstructs early development.

**Tooling and why each is included.**

| Tool | Purpose |
| --- | --- |
| **Ruff** | Fast Python linter and formatter; one tool for style and common-bug linting, keeping the codebase consistent from the first commit. Start with a sensible default rule set, not a maximalist one. |
| **mypy** | Static type checking; the code uses type hints throughout, and mypy catches type errors early. Begin in a pragmatic mode and tighten over time rather than starting maximally strict. |
| **Pytest** | Test runner and configuration (`pyproject.toml`); the foundation for every later phase's tests. |
| **pre-commit** | Runs Ruff (and light checks) locally before each commit, so problems are caught before CI. |
| **GitHub Actions** | CI running lint, type-check and tests on every push/PR. Compose validation is wired **conditionally** — it runs only when a recognised Compose file exists (none yet in Phase 0.5) and becomes **mandatory from Phase 6**, when `docker-compose.yml` is introduced. |

**Licence resolution.** The empty `LICENSE` file is resolved here. **MIT** is recommended for approval (permissive, widely understood, portfolio-friendly, compatible with all planned dependencies). The chosen licence text is added to `LICENSE` and referenced from the README.

**Acceptance criteria.**
- `ruff check` and `ruff format --check` pass on the skeleton.
- `mypy` passes on the skeleton.
- `pytest` runs green (even if only a trivial test exists).
- pre-commit is configured and runs locally.
- GitHub Actions runs lint + type-check + tests and is green. **Compose validation is configured to run only if a recognised Compose file exists** — there is none in Phase 0.5, so it is correctly skipped rather than failing against a nonexistent `docker-compose.yml`. (`docker compose config` and image-build verification become **mandatory in Phase 6**; see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §11.)
- `LICENSE` is populated with the approved licence.

---

## Phase 1 — Backend Skeleton

**Scope.** A minimal, running FastAPI application with configuration and a health endpoint.

**Deliverables.** `backend/app/main.py` (application factory), `backend/app/config.py` (Pydantic Settings with documented, validated defaults), `GET /health`.

**Acceptance criteria.**
- `uvicorn` serves `GET /health` → `{"status": "ok", "version": ...}` with HTTP 200.
- Configuration loads from environment with documented defaults and validation.
- OpenAPI docs (`/docs`) render.
- `pytest` green.

---

## Phase 2 — Detection Engine + Synthetic Events

**Scope.** Typed schemas, the detector interface, both detectors, and a labelled synthetic event generator, all driven by an injected clock.

**Deliverables.** `models/` schemas (`PacketEvent`, `CandidateAlert`, `Alert`); `detection/` interface (detectors return `CandidateAlert`), engine and the `portscan` and `synflood` detectors; `ingest/synthetic.py`.

**Acceptance criteria.**
- Detectors return `CandidateAlert` objects (no `alert_id`/`created_at`/`dedup_key`/AI fields); those are added later by the Alert Engine (Phase 3).
- Feeding a scripted port-scan sequence yields exactly one `portscan` candidate with correct evidence.
- Feeding a scripted SYN-burst sequence yields a `synflood` candidate with correct evidence.
- Threshold boundary tests pass: `N − 1` distinct ports → no alert, `N` → alert; likewise for the SYN detector.
- SYN completion accounting is correct and bounded: an orphan SYN-ACK followed by an ACK adds **no** completion, and `0.0 ≤ completion_ratio ≤ 1.0` holds across the state-machine tests (see [DETECTION_RULES.md](DETECTION_RULES.md) §4.1–§4.2).
- Detector state is partitioned by `source_type`: interleaving synthetic and replay events for the same hosts never merges into one window (§6).
- Window, TTL and cooldown logic is driven by an injected clock over canonical logical event time (no `time.time()` in detectors); out-of-order and unreasonable timestamps are handled per [DETECTION_RULES.md](DETECTION_RULES.md) §2.1.

---

## Phase 3 — Alert Pipeline (Storage, REST, WebSocket)

**Scope.** Persist alerts, apply the cooldown/deduplication gate, expose REST endpoints and the authenticated ingest endpoint, and broadcast live deltas.

**Deliverables.** `storage/` SQLite repository (schema from [ALERT_SCHEMA.md](ALERT_SCHEMA.md)); `alerts/` cooldown/dedup gate (converts `CandidateAlert` → persisted `Alert`); `api/` REST routes and `WS /api/v1/ws/alerts` with `Origin` validation; `POST /api/v1/ingest/events` with `X-Sensor-Token` auth and ingest limits.

**Acceptance criteria.**
- An integration test drives ingest → detection → SQLite row → `GET /api/v1/alerts`.
- A duplicate trigger **within** cooldown updates the existing row (`occurrence_count` increments, `alert.updated` broadcast) rather than inserting; a trigger **after** cooldown inserts a new row (`alert.created`).
- `GET /api/v1/alerts` (filter/paginate), `GET /api/v1/alerts/{id}`, `GET /api/v1/stats` behave as specified.
- Ingest rejects missing/incorrect tokens (token compared in constant time).
- **Ingest limits enforced:** a batch over `INGEST_MAX_BATCH` (200) is rejected; an oversized body is rejected before parsing; a malformed/partially-invalid batch is rejected (422) with nothing partially ingested; a live event with unreasonable timestamp skew is rejected (see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §5.1).
- The exact CORS allowlist is applied (disallowed `Origin` gets no allow headers) and the WebSocket upgrade validates `Origin`.
- A WebSocket test observes a newly ingested alert being pushed.

---

## Phase 4 — Frontend Dashboard

**Scope.** The React + Vite + Recharts dashboard.

**Deliverables.** Overview statistics, live alert feed (WebSocket), filterable/sortable alert table, traffic timeline, protocol distribution, alert-detail view, the traffic-source banner, and an optional AI-explanation section (inert until Phase 7).

**Acceptance criteria.**
- `npm run build` completes cleanly.
- A persistent, unmissable banner shows **SYNTHETIC / REPLAYED / LIVE-LAB** driven by `source_type`.
- The dashboard loads history via REST and applies live deltas via WebSocket, with graceful reconnect and sensible empty/error states.
- Component tests cover the alert table/feed and the banner logic.

---

## Phase 5 — PCAP Replay + Scapy Hardening

**Scope.** The first real ingestion path and robust packet parsing.

**Deliverables.** `scripts/generate_pcaps.py` (Scapy `wrpcap`, unprivileged); `ingest/pcap_replay.py` with timing control (respect or accelerate inter-packet gaps).

**Acceptance criteria.**
- `generate_pcaps.py` produces the scenario PCAPs from a clean clone without privileges; PCAPs are never committed and never downloaded from external links.
- Replaying the port-scan PCAP produces the expected `portscan` alert.
- The replay ingester tolerates malformed, truncated, non-IP, IPv6 and unexpected-protocol frames without crashing (malformed-packet corpus test passes; see [TESTING_STRATEGY.md](TESTING_STRATEGY.md)).

---

## Phase 6 — Docker Lab + Live Sidecar Capture

**Scope.** The isolated Compose lab and live capture via the sidecar sensor.

**Deliverables.** `docker-compose.yml` and `lab/` per [NETWORK_DESIGN.md](NETWORK_DESIGN.md): victim, generator, sensor, backend, frontend; the normal-traffic, port-scan and SYN-burst scenarios.

**Acceptance criteria.**
- `docker compose config` validates; `docker compose up` brings all services healthy.
- Running the port-scan scenario against the victim produces a live alert visible on the dashboard within the detection window.
- The self-capture control is verified at **both** enforcing layers: the kernel BPF exclusion filter **and** the sensor-side userspace filter (applied before `PacketEvent` creation / batch enqueueing). With each in force the sensor↔backend ingest connection does not appear as events and no feedback loop forms (see [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §8).
- Container audit confirms non-root users, dropped capabilities, no `privileged`, and that no published host port binds to `0.0.0.0` (only the two loopback mappings are published).
- **Sensor capability test (executable, not asserted).** The sensor's `NET_RAW` mechanism is proven by inspecting the *actual* process capability sets (e.g. `CapEff`/`CapAmb` from `/proc/<pid>/status`, `getpcaps`), demonstrating raw-socket capture works with **only `NET_RAW`** effective under `no-new-privileges: true` and no `privileged` — using either a verified non-root ambient-capability configuration or the narrowly scoped root-in-container fallback (see [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §10.1). `setcap` on the interpreter is not used.

---

## Phase 7 — AI Explanation Layer

**Scope.** The optional AI Security Analyst that explains existing alerts, with a deterministic fallback. See [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md).

**Deliverables.** `ai/` provider abstraction (`DisabledProvider` default, `TemplateFallbackProvider`, and a provider-independent hosted HTTP provider), the sanitisation allowlist, and the orchestration service (cache, rate limit, timeout, retries, fallback).

**Acceptance criteria.**
- The application is fully functional with the AI disabled and no API key.
- The sanitiser unit tests prove only allowlisted fields can leave the process; raw IPs never leave.
- Timeout → fallback, rate-limit → fallback, cache hit avoids a provider call, disabled mode returns deterministic text — all covered by tests using a mock provider (no live network).
- **Input/output controls** (see [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md) §6.1): an oversized serialised `AlertSummary` or too-many-evidence-fields → fallback (never sent); an over-limit, empty, malformed or schema-invalid provider response → fallback; explanation text renders with no unsanitised HTML; retries fire only on transient failures (timeout/`5xx`/`429`) and **not** on ordinary `4xx`.
- Explanations are clearly labelled as AI-generated or deterministic fallback; `ai_status` transitions correctly.

---

## Phase 8 — Hardening and Polish

**Scope.** Raise the project to portfolio finish.

**Acceptance criteria.**
- Coverage gate met: ≥ 85% on backend `detection/`, `alerts/`, `models/`.
- Security pass: no secrets committed, capability/`cap_drop` audit clean, only loopback ports published.
- Documentation regenerated for any changes; README includes screenshots/GIF; a CHANGELOG exists.

---

## Post-V1

### Suricata Integration
A Suricata `eve.json` ingester will normalise Suricata events into `PacketEvent`/alert objects behind the **same** interfaces the V1 detectors use, so a mature, signature-based engine can join the pipeline without changing detection, storage or the dashboard. This is the "professional tooling" step and demonstrates integrating an industry-standard IDS.

### Deployment
Hardened deployment (reverse proxy, TLS, authenticated non-loopback exposure, secrets management) is out of V1 scope. It is recorded as future work; V1 remains a loopback-bound, isolated-lab tool.

---

## Recommended Next Phase

**Phase 0.5 — Tooling and CI Baseline** (approved), which also resolves the licence decision.
