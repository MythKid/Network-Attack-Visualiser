# Project Progress

**Last updated:** 2026-07-17

This file tracks delivery progress. It is updated at the end of every completed phase.

**Related documents:** [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md), [PROJECT_SCOPE.md](PROJECT_SCOPE.md), [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Completed Work

### Phase 0 — Design Documentation (authored 2026-07-14; reviewed, committed and pushed 2026-07-15)
The full design documentation set has been authored under `docs/`, plus a rewritten root `README.md`:

- [PROJECT_SCOPE.md](PROJECT_SCOPE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [NETWORK_DESIGN.md](NETWORK_DESIGN.md)
- [DETECTION_RULES.md](DETECTION_RULES.md)
- [ALERT_SCHEMA.md](ALERT_SCHEMA.md)
- [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)
- [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md)
- [TESTING_STRATEGY.md](TESTING_STRATEGY.md)
- [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md)
- [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) (this file)
- `README.md` (repository root)

**Pre-commit technical-correction pass (2026-07-15).** Before Phase 0 was committed, the set was reviewed and corrected for internal consistency: a three-layer self-capture model (BPF / userspace / backend, with the transport-loop distinction); the `NET_RAW` decision reframed as a Phase 6 executable capability test (`setcap` ruled out under `no-new-privileges`); a corrected SYN completion-ratio accounting (`syn_observed`-gated, cohort-bounded, `0.0 ≤ ratio ≤ 1.0`); a new internal `CandidateAlert` detector-output schema distinct from the persisted `Alert`; `source_type` folded into detector-state keys and dedup identity; clarified container/host bindings plus an exact CORS allowlist and WebSocket `Origin` validation; explicit AI input/output limits and validation; canonical logical event-time semantics for replay/live parity; backend ingest limits (batch/body/schema/skew, constant-time token compare); conditional Phase 0.5 Compose validation; and corrected README wording.

### Phase 0.5 — Tooling and CI Baseline (completed 2026-07-15)
The quality and continuous-integration baseline is in place, and the licence decision is resolved. No application code, containers or application dependencies were added — only development tooling and the minimum package/test skeleton to validate it.

- **`pyproject.toml`** — Ruff (lint + format, `py312`, proportionate rule set `E,F,I,B,UP,SIM,C4,RUF`), pragmatic mypy (typed but not `strict`), and Pytest configuration.
- **`requirements-dev.txt`** — pip-compatible, exact-pinned dev tools: `ruff==0.15.21`, `mypy==2.3.0`, `pytest==9.1.1`, `pre-commit==4.6.0`. No package manager (Poetry/uv/…); no application dependencies.
- **Minimal skeleton** — `backend/app/__init__.py` (typed `__version__`, `py.typed`) and `backend/tests/test_baseline.py` so the tools have real code to validate.
- **`.pre-commit-config.yaml`** — Ruff plus lightweight repository-hygiene hooks (whitespace, EOF, YAML/TOML, merge-conflict, large-file and private-key checks). mypy is CI-only, by design.
- **`.github/workflows/ci.yml`** — Python 3.12, dependency caching, `ruff check` / `ruff format --check` / `mypy` / `pytest` / `pre-commit`, least-privilege `contents: read`, and **conditional** Compose validation (skips cleanly until a Compose file exists; mandatory from Phase 6).
- **`LICENSE`** — MIT, Copyright (c) 2026 Methindu Damsara.

### Phase 1 — Backend Skeleton (completed 2026-07-15)
A minimal, running FastAPI backend is in place, with application creation, configuration, routing and response models kept cleanly separated:

- **`backend/app/main.py`** — the `create_app(settings)` application factory (settings are injectable, so tests build isolated apps without touching global state), a module-level `app` for ASGI servers, and a `python -m app.main` development runner bound to the configured host/port.
- **`backend/app/config.py`** — typed, environment-driven `Settings` (Pydantic Settings) with documented, validated defaults: `app_name`, `app_version` (defaults to the packaged `__version__`, overridable via `APP_VERSION`), `environment`, `host`, `port`. Empty/whitespace-only strings, out-of-range ports and unknown environments are rejected clearly. A cached `get_settings()` accessor is used only at application construction.
- **`backend/app/api/`** — `GET /health` → `{"status": "ok", "version": <app version>}`, the typed `HealthResponse` model, and OpenAPI docs at `/docs`.
- **Dependencies** — runtime deps pinned in `requirements.txt` (`fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`); `httpx2` added to `requirements-dev.txt` for the FastAPI/Starlette `TestClient` (the current Starlette `TestClient` prefers `httpx2`). CI now installs runtime **and** dev dependencies, and the Pydantic mypy plugin is enabled.
- **Tests** — deterministic unit tests for application creation, the health response and its typed schema, version propagation, OpenAPI/`/docs` availability, and configuration validation.
- **`.env.example`** — documents the Phase 1 variables with non-secret defaults.
- **Version** — package `__version__` bumped `0.0.0` → `0.1.0`.

### Phase 2 — Detection Engine + Synthetic Events (completed 2026-07-16)
The first correctness-critical logic is in place: typed domain schemas, the clock-injected detector interface, both heuristic detectors, and a deterministic synthetic event generator. Everything is pure and driven by canonical logical event time — no real clock is read in the detection path — and covered by an extensive deterministic test suite.

- **`backend/app/models/`** — the Phase 2 data model (see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)): `PacketEvent` (source-agnostic, metadata-only transport DTO; nullable ports/flags preserved for incomplete parsing), `CandidateAlert` (detector output with typed `PortScanEvidence` / `SynFloodEvidence`, and **no** identity/dedup/AI fields), and the persisted-shape `Alert` (defined, not populated). Shared validators enforce UUIDv4 identities, IP-address strings, finite/ordered timestamps and JSON-only evidence values.
- **`backend/app/detection/`** — the `Detector` protocol (`update`/`expire` from [DETECTION_RULES.md](DETECTION_RULES.md) §2, plus an additive `max_event_age_s` the engine uses to derive its acceptance horizon); the `DetectionEngine`, which advances a **per-`source_type`** monotonic high-water mark from `PacketEvent.ts`, applies the out-of-order / too-late policy, and drives expiry; and the `portscan` and `synflood` detectors. State is nested by `source_type` (strict cross-provenance isolation even under widely divergent timelines); windows are safe against out-of-order insertion; emission is severity-aware and re-armable; and the SYN detector uses observed-SYN-gated completion accounting with stable per-attempt identity so `0.0 ≤ completion_ratio ≤ 1.0` always holds. Thresholds come from `DetectionSettings` (the **11** documented environment variables).
- **`backend/app/ingest/synthetic.py`** — deterministic, `source_type="synthetic"` normal / port-scan / SYN-burst sequences, with collision-free event ids from an injective scenario-and-counter UUIDv4 factory.
- **Tests** — 265 deterministic tests (schema validation, config, engine event-time policy, threshold and severity boundaries, sliding-window and TTL boundaries, the full SYN handshake state machine including orphan-SYN-ACK and reversed-tuple direction handling, state-creation gates, source-aware expiry, non-finite rejection, cross-source isolation, and synthetic labelling/determinism). `ruff`, `ruff format`, `mypy`, `pytest` and `pre-commit` all pass.
- **Dependencies** — none added; detection uses only Pydantic (already pinned) and the standard library.
- **Version** — package `__version__` bumped `0.1.0` → `0.2.0`, marking the completed Phase 2 detection functionality. `GET /health` and the OpenAPI schema report `0.2.0`; `.env.example` documents the matching `APP_VERSION` default, and the version continues to be derived from `__version__` rather than duplicated in code.
- **Out of scope (deferred to Phase 3+)** — the Alert Engine, deduplication/cooldown, SQLite storage, REST/WebSocket ingest and the AI layer.

**Pre-commit correction pass (2026-07-16).** A final independent review found correctness gaps that the original 133 tests did not cover. All were fixed during the Phase 2 pre-commit correction pass, and each is now covered by direct regression tests:

- **SYN-flood mutation ordering.** Packets are now classified and age-gated **before** any state is created: an out-of-window SYN, an age-gated SYN-ACK/ACK/RST, a bare ACK and an unmatched RST previously each materialised an empty target key and refreshed its idle TTL, so ignored traffic could both leak memory and hold dead keys open indefinitely. A key's last-activity time now advances only when a packet actually creates, progresses, completes or removes state.
- **SYN-ACK evidence window.** SYN-ACK *progression* (`HANDSHAKE_TTL_S`) is now separated from *evidence accounting* (`SYN_WINDOW_S`), so a SYN-ACK from outside the reported window can no longer inflate `synack_count` for a burst it was never part of.
- **Expiry interface.** `expire(now)` ignored the logical time it was given (sweeping every partition against its own high-water mark) because a single global `now` could not be applied without one provenance's clock ageing out another's state. The contract is now `expire(source_type, now)`: the supplied time is genuinely honoured, for exactly one partition. This is a deliberate, documented change to the `Detector` protocol in [DETECTION_RULES.md](DETECTION_RULES.md) §2 and [TESTING_STRATEGY.md](TESTING_STRATEGY.md) §2.
- **Non-finite values rejected.** Pydantic's `JsonValue` accepted `NaN`/`±Infinity` and serialised them to `null`, silently destroying evidence; they are now rejected recursively at any nesting depth in `evidence` and `threshold_snapshot` on both `CandidateAlert` and `Alert`. Detection configuration and the engine's acceptance horizons likewise reject non-finite values, which `float()` would otherwise parse straight out of an environment variable — an infinite window disables expiry, and `NaN` disables detection, both silently.

### Phase 3 — Alert Pipeline: Storage, REST, WebSocket (completed 2026-07-17)
The pipeline beyond detection now exists end to end: an authenticated batch of events flows through detection, becomes a persisted alert row, is served over REST and is pushed live to WebSocket subscribers. The full REST/WebSocket contract is a new document, [API.md](API.md).

- **`backend/app/storage/`** — one `Database` object owns the single SQLite connection *and* the lock that guards it (two repositories with independent locks would serialise nothing). Transactions are thread-owned (`threading.get_ident()`), non-nestable, `BEGIN IMMEDIATE`, rollback-on-any-exception with the original error always preserved; repository writes verify the calling thread owns the open transaction, so a foreign thread can neither join nor escape it. Multi-query logical reads (`GET /alerts` page+count; the whole `/stats` snapshot) run inside a `read_session` holding the lock, making each response internally consistent. WAL is applied and asserted for file databases only (SQLite silently ignores it for `:memory:`); the database file is created `0600`. Ordering and the `ALERT_MAX_ROWS` row cap use **insertion order (`rowid`)**, never `created_at` — logical event time is not comparable across provenances. Stored JSON is refused non-finite values in both directions (`allow_nan=False` on write, `parse_constant` rejection on read).
- **`backend/app/alerts/`** — the Alert Engine implements the [DETECTION_RULES.md](DETECTION_RULES.md) §5 gate: dedup key `sha1(detector:vMAJOR:source_type:src:dst)`, in-memory gate partitioned by `(source_type, detector_id)` holding exactly `{latest_alert_id, last_fired_at}`, cooldown fixed from row creation (never refreshed by updates), severity escalate-only, evidence/confidence refreshed, `window_end` extended, `window_start` preserved. A dangling gate reference (row pruned or rolled back) recovers by creating a fresh row. The `EventPipeline` serialises the whole batch under one lock in three phases (compute → one transaction → gate sweep, with the sweep also running on the failure path so storage failures cannot accumulate stale gate entries); pruning runs once near the end of the transaction and **deltas are returned, counted and broadcast only if their row survives at commit**. The `AlertBroadcaster` fans a once-serialised envelope out to bounded per-subscriber queues; a consumer that falls behind is closed with `1013` to re-sync via REST rather than silently skipping deltas.
- **`backend/app/api/`** — `GET /api/v1/alerts` (filter/paginate, newest-recorded first), `GET /api/v1/alerts/{id}`, `GET /api/v1/stats` (one consistent snapshot; provenance-aware timeline buckets; both `alert_count` and `alert_occurrence_total`), `POST /api/v1/ingest/events`, and `WS /api/v1/ws/alerts` (`Origin` validated before accept; concurrent sender + disconnect-watcher tasks under an anyio task group so idle disconnects free their subscriptions). The ingest guard — the body-size cap by declared *and* counted bytes **and** the constant-time `X-Sensor-Token` check (fail-closed 503 when unconfigured) — is a pure-ASGI middleware running **before FastAPI reads or parses the body**, because FastAPI decodes the body ahead of route dependencies; a route-level dependency is retained as documented defence in depth. Whole-batch schema validation, the batch cap and live clock-skew rejection (synthetic/replay exempt) follow. Read endpoints are synchronous `def` routes and ingest uses `run_in_threadpool`, so no sqlite3 call ever blocks the event loop. After the batch transaction commits, **no failure — publication or gate cleanup — can turn the committed ingest into an error response**: logged, `202` returned, REST authoritative.
- **Tests** — 401 total (265 Phase 2 tests unchanged + 136 new): transaction/ownership/read-session threading tests, cooldown boundary tests on injected logical time, the `ALERT_MAX_ROWS=1` same-batch prune regression, rollback and gate-recovery tests, ingest limit/skew/precedence tests (including malformed-JSON probes proving the token verdict precedes body parsing, and post-commit gate-cleanup/publication failure regressions), WebSocket handler-contract tests (overflow → close `1013`, disconnect races as normal completion, cancellation never suppressed), CORS and WebSocket origin tests, and an automated **real-uvicorn** WebSocket test (real upgrade over a real socket with the pinned `websockets` client) — the TestClient fakes the WS transport and cannot prove upgrades work. `pytest` and `pytest -W error` both pass.
- **Dependencies** — one addition: `websockets==16.1` (BSD-3-Clause, pure Python, uvicorn's default WS protocol; plain uvicorn ships no WebSocket implementation, so without it every real upgrade fails while TestClient tests stay green).
- **Configuration** — new documented variables: `DATABASE_PATH`, `CORS_ALLOW_ORIGINS` (wildcards rejected on load), `SENSOR_TOKEN` (secret, min 16 chars, no default), `INGEST_MAX_BATCH`, `INGEST_MAX_BODY_BYTES`, `MAX_CLOCK_SKEW_S`, `ALERT_MAX_ROWS`, `WS_MAX_QUEUE`.
- **Version** — `0.2.0` → `0.3.0`.

---

## Current Phase

**Phase 3 — Alert Pipeline (Storage, REST, WebSocket): complete** (application version `0.3.0`). Ingest → detection → SQLite → REST → WebSocket works end to end and is covered by 401 deterministic tests; `ruff check`, `ruff format --check`, `mypy`, `pytest`, `pytest -W error` and `pre-commit` all pass locally.

The frontend dashboard, PCAP replay, the Docker lab with live capture, and the AI layer do not exist yet. This is by design: development proceeds one approved phase at a time. The next planned unit of work is Phase 4 (frontend dashboard).

---

## Remaining Work

| Phase | Title | Status |
| --- | --- | --- |
| 0.5 | Tooling and CI baseline (Ruff, mypy, Pytest config, pre-commit, GitHub Actions); resolve licence | **Complete** |
| 1 | Backend skeleton (FastAPI, health endpoint, config) | **Complete** |
| 2 | Detection engine + synthetic events | **Complete** |
| 3 | Alert pipeline (SQLite storage, dedup/cooldown, REST, WebSocket) | **Complete** |
| 4 | Frontend dashboard | Planned (next) |
| 5 | PCAP replay + Scapy hardening | Planned |
| 6 | Docker lab + live sidecar capture | Planned |
| 7 | AI explanation layer | Planned |
| 8 | Hardening and polish | Planned |
| Post-V1 | Suricata integration; hardened deployment | Future |

Acceptance criteria for each phase are in [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md).

---

## Known Issues and Open Decisions

- **`event_stats` is unbounded in Phase 3.** Time-based retention (`ALERT_RETENTION_DAYS`, `STATS_RETENTION_HOURS`) is deferred — retention days are wall-clock quantities while all stored timestamps are logical event time, and reconciling the two needs a reviewed design. Only the alert row cap (`ALERT_MAX_ROWS`) is enforced. Growth is bounded in rate (at most 12 rows per event-time second) and the database is ephemeral, deletable lab data; `STATS_RETENTION_HOURS=24` is the first candidate for whichever later phase takes on retention (Phase 8 hardening is the natural home).
- **Reads serialise behind ingest writes.** One shared SQLite connection: a `GET` issued while a batch commits waits for its write phase. WAL's concurrent-reader benefit needs separate reader connections — the natural upgrade if Phase 4 dashboard polling ever contends with Phase 6 live ingest (see [ARCHITECTURE.md](ARCHITECTURE.md) §5.4).
- **Ingest is non-idempotent and retry-unsafe.** Documented for future sensor authors in [API.md](API.md) §6.1: neither a 500 nor a timeout may be blindly retried. A sensor-side delivery policy is a Phase 6 design item.
- **The dedup/cooldown gate is in-memory.** A backend restart inside a cooldown window produces a new alert row on the next trigger rather than reinforcing the pre-restart row (per the documented gate design in [DETECTION_RULES.md](DETECTION_RULES.md) §5).
- **Licence (resolved 2026-07-15).** Resolved in Phase 0.5: the project is licensed under the **MIT License** (`LICENSE`, Copyright (c) 2026 Methindu Damsara), referenced from the README. No longer an open decision.
- **Lab subnet collision check.** The lab uses `172.28.0.0/24` by default (overridable via `LAB_SUBNET`). A pre-flight collision check must be run before `docker compose up`; procedure documented in [NETWORK_DESIGN.md](NETWORK_DESIGN.md).
- **Sensor `NET_RAW` capability approach.** `setcap cap_net_raw+eip` on the Python interpreter is **ruled out** because it conflicts with the mandatory `no-new-privileges: true` policy (the kernel ignores file capabilities on `execve` under `no_new_privs`). The mechanism is resolved by an **executable capability test in Phase 6** between exactly two candidates: (1) a verified non-root **ambient-capability** configuration (preferred if proven on the built image), or (2) a narrowly scoped **root-in-container** fallback (`cap_drop: [ALL]`, `cap_add: [NET_RAW]`, `no-new-privileges: true`, no `privileged`). Acceptance inspects the actual process capability sets. Full analysis in [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §10.1.

**Not an open decision:** the container runtime is settled — **Docker Desktop with WSL 2 integration on Ubuntu-26.04**, enabled and verified. No native Docker Engine will be installed in Ubuntu.

---

## Next Milestone

**Phase 4 — Frontend Dashboard** (React + Vite + Recharts over the Phase 3 API: REST history plus WebSocket deltas per [API.md](API.md), overview statistics, live alert feed, filterable alert table, traffic timeline, protocol distribution, alert detail, and the persistent SYNTHETIC / REPLAYED / LIVE-LAB banner). Phase 4 must render alert timestamps as *event* time — never wall-clock-relative — per [API.md](API.md) §1.1. See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md). Not started; awaits explicit approval.
