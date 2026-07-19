# Network Attack Visualiser

[![CI](https://github.com/MythKid/Network-Attack-Visualiser/actions/workflows/ci.yml/badge.svg)](https://github.com/MythKid/Network-Attack-Visualiser/actions/workflows/ci.yml)

Real-time detection and visualisation of network attacks in an **isolated, authorised Docker laboratory**. The system ingests network traffic, runs transparent heuristic detectors (TCP port scans and suspicious SYN activity), stores alerts, and presents them live on a web dashboard.

This is a **defensive** networking and cybersecurity project, developed as a student portfolio project and built to graduate-level standards.

---

## ⚠️ Defensive Use Only

This project is for **education, research and authorised laboratory environments only**. It must never be used against systems you do not own or are not explicitly authorised to test. It contains no offensive malware, no persistence mechanisms and no credential-theft capability, and it never targets third-party systems. See [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md) and [docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md).

---

## Project Status

**Phases 0 through 5 are complete.** On top of the design specification (Phase 0), the CI baseline (Phase 0.5), the backend skeleton (Phase 1), the detection engine with synthetic events (Phase 2), the **alert pipeline** (Phase 3 — SQLite storage, the cooldown/deduplication Alert Engine, REST endpoints, a sensor-authenticated ingest endpoint and live `alert.created` / `alert.updated` deltas over WebSocket) and the **frontend dashboard** (Phase 4 — a React + Vite + TypeScript + Recharts single-page app that loads history over REST, applies live deltas over WebSocket under a bounded, single-flight, version-aware synchronisation protocol, and presents overview statistics, a filterable alert feed, protocol-distribution and per-provenance traffic-timeline charts, an alert-detail view, and an unmissable **SYNTHETIC / REPLAYED / LIVE-LAB** provenance banner), **PCAP replay** (Phase 5) is now in place. An unprivileged generator (`scripts/generate_pcaps.py`) produces the scenario captures locally, and a streaming, hardened Scapy ingester (`app.ingest.pcap_replay`, driven by `scripts/replay_pcap.py`) feeds them through the same detection, alert and statistics pipeline as `source_type="replay"` — in-process and never over the network, extracting only packet metadata. Timestamps render as logical event time (synthetic and replay as event-time seconds, never wall-clock-relative). The Docker lab and the optional AI layer are introduced in later phases — development proceeds one approved phase at a time.

- Current progress: [docs/PROJECT_PROGRESS.md](docs/PROJECT_PROGRESS.md)
- Phase plan and acceptance criteria: [docs/DEVELOPMENT_PHASES.md](docs/DEVELOPMENT_PHASES.md)
- REST and WebSocket API contract: [docs/API.md](docs/API.md)

---

## Planned Version 1 Capabilities

- **Staged traffic ingestion** — deterministic synthetic events, then controlled PCAP replay, then live capture from the isolated Docker lab (Suricata integration is post-V1).
- **Two heuristic detectors** — a TCP port-scan detector and a suspicious SYN-activity detector, with configurable thresholds, sliding windows, state expiry and alert cooldown.
- **Alert pipeline** — SQLite storage, deduplication with well-defined update semantics, REST endpoints, and WebSocket broadcasting of live alerts.
- **Live dashboard** — overview statistics, live alert feed, alert table, traffic timeline, protocol distribution, alert details, and an unmissable indicator of whether traffic is synthetic, replayed or live-lab.
- **Isolated lab** — a private Docker network with an Nginx victim (never published), a safe traffic generator, and normal / port-scan / SYN-burst scenarios.
- **Optional AI explanations** — an optional layer that explains existing alerts in plain language, receiving only sanitised metadata, with a deterministic fallback. The application works fully without it.

---

## Technology Stack

| Layer | Technology |
| --- | --- |
| Backend | Python 3.12+, FastAPI, native WebSockets |
| Packet handling | Scapy |
| Storage | SQLite |
| Frontend | React (Vite), Recharts |
| Testing | Pytest |
| Orchestration | Docker Compose |
| Environment | Docker Desktop with WSL 2 integration (Ubuntu-26.04) |

---

## Documentation

| Document | Purpose |
| --- | --- |
| [docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md) | V1 scope, exclusions, ethics and limitations. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, repository structure, data flow, key decisions. |
| [docs/NETWORK_DESIGN.md](docs/NETWORK_DESIGN.md) | Docker topology, the bridge traffic-visibility problem, capture strategy, WSL 2 caveats, privileges. |
| [docs/DETECTION_RULES.md](docs/DETECTION_RULES.md) | Detector specifications, thresholds, severity, evidence, cooldown, false positives. |
| [docs/ALERT_SCHEMA.md](docs/ALERT_SCHEMA.md) | Typed event and alert schemas, SQLite DDL, retention and privacy. |
| [docs/API.md](docs/API.md) | REST and WebSocket contract: endpoints, semantics, limits, retry safety. |
| [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md) | Defensive mandate, container privilege, exposure, secrets, privacy. |
| [docs/DEVELOPMENT_PHASES.md](docs/DEVELOPMENT_PHASES.md) | Phased delivery plan with acceptance criteria. |
| [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) | Testing approach across all phases. |
| [docs/AI_EXPLANATION_DESIGN.md](docs/AI_EXPLANATION_DESIGN.md) | Optional AI explanation layer design. |
| [docs/PROJECT_PROGRESS.md](docs/PROJECT_PROGRESS.md) | Live progress tracker. |

---

## Development

The repository ships with a lightweight, pip-compatible tooling baseline. Runtime dependencies are pinned in [requirements.txt](requirements.txt) and development tools in [requirements-dev.txt](requirements-dev.txt); their configuration lives in [pyproject.toml](pyproject.toml).

```bash
# From the repository root
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt

# Optional: install the git pre-commit hook
pre-commit install
```

### Running the backend

Run from the repository root so the root `.env` is loaded. Either invocation works:

```bash
uvicorn --app-dir backend app.main:app     # ASGI server
PYTHONPATH=backend python -m app.main       # module entry point
```

Then:

- Health check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) → `{"status": "ok", "version": "0.4.0"}`
- Interactive API docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Alerts and statistics: `GET /api/v1/alerts`, `GET /api/v1/stats`; live deltas on `WS /api/v1/ws/alerts` — full contract in [docs/API.md](docs/API.md)

Configuration is environment-driven with validated defaults; copy [.env.example](.env.example) to `.env` to override any value. The SQLite database is created at `DATABASE_PATH` (default `data/nav.sqlite3`) on startup — ephemeral lab data, git-ignored, safe to delete. The sensor ingest endpoint (`POST /api/v1/ingest/events`) requires a `SENSOR_TOKEN` to be configured and **fails closed with HTTP 503 until one is set**; it authenticates server-to-server sensors only and is never called by the browser.

### Running the frontend

The dashboard is a React + Vite + TypeScript app in [frontend/](frontend/). It is **read-only**: it calls the backend's `GET` endpoints and the WebSocket feed directly (cross-origin, governed by the backend CORS allowlist) and never holds the sensor token or calls the ingest endpoint.

```bash
cd frontend
npm ci
npm run dev        # Vite dev server on http://localhost:5173 (strict port)
```

The dev server is pinned to port **5173** to match the backend's default CORS / WebSocket `Origin` allowlist. The Node major is pinned by [frontend/.nvmrc](frontend/.nvmrc). Configure the backend URL with `VITE_API_BASE_URL` (default `http://localhost:8000`, from which the WebSocket URL is derived); copy [frontend/.env.example](frontend/.env.example) to `frontend/.env` to override. Other scripts:

```bash
npm run build          # tsc -b && vite build (production bundle in frontend/dist)
npm run lint           # eslint
npm run typecheck      # tsc -b --noEmit
npm run test -- --run  # vitest (jsdom)
```

To see live data during development, run the Phase 3 backend with a `SENSOR_TOKEN` set and post synthetic events to `POST /api/v1/ingest/events` from a **server-side** script or `curl` (never from the browser).

### PCAP replay (Phase 5)

Replay runs **in-process and never crosses the network** — it is not exposed as an HTTP endpoint and there is no upload mechanism. Generate the scenario captures locally (unprivileged; captures are git-ignored and never committed), then replay one into the pipeline:

```bash
python scripts/generate_pcaps.py                 # writes captures/{normal_traffic,port_scan,syn_burst}.pcap
python scripts/replay_pcap.py captures/port_scan.pcap        # as fast as possible
python scripts/replay_pcap.py captures/port_scan.pcap --speed 1   # paced at real time (>0, finite)
```

Every replayed event is `source_type="replay"` (this cannot be overridden), and only packet metadata is used — payloads are never read, stored or logged. Replay writes alerts to the configured `DATABASE_PATH`; the `REPLAY_*` variables in [.env.example](.env.example) bound file size, record count, batch size and pacing sleeps. Exit codes: `0` completed, `2` usage/invalid `--speed`, `3` packet-limit reached, `4` truncated capture, `5` a file-level `ReplayError`.

**Visibility in a running dashboard.** The `replay_pcap.py` process runs separately from any live API server, so it does **not** push live WebSocket deltas to an open dashboard. Overview statistics refresh on their poll interval (~5 s); the **alert table** refreshes only when you change the provenance filter, reload, reconnect, or trigger a retry — this is the existing Phase 4 behaviour. Select the **REPLAYED** provenance to view replay alerts.

### Quality checks

Quality checks (all run in CI on Python 3.12 for every push and pull request):

```bash
ruff check .            # lint
ruff format --check .   # formatting
mypy                    # static type checking
pytest                  # tests
pre-commit run --all-files
```

A separate **`frontend`** CI job runs the dashboard's ESLint, type-check, Vitest suite and `vite build` on the Node major pinned in [frontend/.nvmrc](frontend/.nvmrc). Docker Compose validation is wired into CI **conditionally**: it is skipped while no Compose file exists and becomes a mandatory gate in Phase 6, when `docker-compose.yml` is introduced.

---

## Licence

Licensed under the **GNU General Public License, version 2 only (GPL-2.0-only)** — see [LICENSE](LICENSE). Copyright (c) 2026 Methindu Damsara.

**Why GPL-2.0-only.** From Phase 5 the project depends on [Scapy](https://scapy.net/), which is distributed under GPL-2.0-only, and imports it as a library. Adopting GPL-2.0-only for the project going forward is the chosen **conservative compliance posture** for combining with that dependency. This is a project licensing decision, **not legal advice**; the relevant copyright holders should be consulted before relying on it. The change applies to future releases only — **previously released versions remain available under the MIT licence they were published under**, and any future relicensing depends on the agreement of the relevant copyright holders.
