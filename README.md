# Network Attack Visualiser

Real-time detection and visualisation of network attacks in an **isolated, authorised Docker laboratory**. The system ingests network traffic, runs transparent heuristic detectors (TCP port scans and suspicious SYN activity), stores alerts, and presents them live on a web dashboard.

This is a **defensive** networking and cybersecurity project, developed as a student portfolio project and built to graduate-level standards.

---

## ⚠️ Defensive Use Only

This project is for **education, research and authorised laboratory environments only**. It must never be used against systems you do not own or are not explicitly authorised to test. It contains no offensive malware, no persistence mechanisms and no credential-theft capability, and it never targets third-party systems. See [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md) and [docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md).

---

## Project Status

**Design phase (Phase 0) complete.** There is **no application code yet** — this repository currently contains the full Version 1 design specification. Development proceeds one approved phase at a time.

- Current progress: [docs/PROJECT_PROGRESS.md](docs/PROJECT_PROGRESS.md)
- Phase plan and acceptance criteria: [docs/DEVELOPMENT_PHASES.md](docs/DEVELOPMENT_PHASES.md)

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
| [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md) | Defensive mandate, container privilege, exposure, secrets, privacy. |
| [docs/DEVELOPMENT_PHASES.md](docs/DEVELOPMENT_PHASES.md) | Phased delivery plan with acceptance criteria. |
| [docs/TESTING_STRATEGY.md](docs/TESTING_STRATEGY.md) | Testing approach across all phases. |
| [docs/AI_EXPLANATION_DESIGN.md](docs/AI_EXPLANATION_DESIGN.md) | Optional AI explanation layer design. |
| [docs/PROJECT_PROGRESS.md](docs/PROJECT_PROGRESS.md) | Live progress tracker. |

---

## Licence

**Licence selection is in progress.** The `LICENSE` file is intentionally not yet populated; licence choice is recorded as an open decision (MIT recommended) to be resolved in Phase 0.5. See [docs/PROJECT_PROGRESS.md](docs/PROJECT_PROGRESS.md).
