# Project Scope

**Document status:** Partially implemented; this document defines the agreed Version 1 (V1) scope in full. **Implemented through Phase 2:** the FastAPI backend skeleton (application factory, typed configuration, health endpoint); the typed `PacketEvent`, `CandidateAlert` and `Alert` models with their typed evidence models; the `Detector` interface and the `DetectionEngine`; the `portscan` and `synflood` detectors; configurable detector windows and TTLs; and the deterministic synthetic event scenarios (stage 1 of the ingestion progression in §4). **Planned for later phases:** the alert lifecycle, deduplication and cooldown handling; SQLite persistence and event statistics; the REST ingest and alert APIs; WebSocket broadcasting; the frontend dashboard; PCAP replay; live capture and the Docker lab topology; and AI explanations. See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) for current status.

**Related documents:** [ARCHITECTURE.md](ARCHITECTURE.md), [NETWORK_DESIGN.md](NETWORK_DESIGN.md), [DETECTION_RULES.md](DETECTION_RULES.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md), [TESTING_STRATEGY.md](TESTING_STRATEGY.md), [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md), [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md).

---

## 1. Purpose and Goals

The Network Attack Visualiser is a **defensive** networking and cybersecurity application. It is designed to:

- Ingest network traffic from an isolated, authorised laboratory environment.
- Detect suspicious network behaviour using transparent, deterministic heuristics.
- Store the resulting alerts and visualise them in real time on a web dashboard.
- Demonstrate networking, cybersecurity and software-engineering competence to the standard expected of a graduate portfolio project.

The project is intended solely for **education, research and authorised laboratory environments**. It is not a production intrusion-detection system, and it must never be pointed at systems the operator does not own or is not explicitly authorised to test.

The goals, in priority order, are:

1. **Correctness and honesty** — heuristic detections are clearly labelled as heuristics, with documented false positives and limitations. The system never claims certainty.
2. **Security and privacy by design** — only traffic metadata is processed; payloads and credentials are never stored, logged or transmitted.
3. **Clean, maintainable architecture** — clear separation between capture, detection, storage, API and presentation.
4. **Reproducibility** — the whole system runs from a clean clone in a self-contained Docker Compose lab, with deterministic demonstration scenarios.

---

## 2. Development Environment (agreed)

The agreed and verified V1 development and runtime environment is **Docker Desktop with WSL 2 integration on Ubuntu-26.04**. Docker Desktop integration is enabled and confirmed working inside WSL (`docker run --rm hello-world` succeeds), with the `docker-desktop` utility distribution running alongside `Ubuntu-26.04` under WSL 2. No second, native Docker Engine will be installed inside Ubuntu.

The visibility consequences of this environment (Docker bridge interfaces living inside the Docker Desktop utility VM, and why the capture design is deliberately independent of host-side bridge access) are analysed in detail in [NETWORK_DESIGN.md](NETWORK_DESIGN.md).

---

## 3. Version 1 Technology Choices

| Layer | Technology |
| --- | --- |
| Language (backend) | Python 3.12+ |
| Packet handling | Scapy |
| Web framework | FastAPI |
| Real-time transport | Native FastAPI WebSockets |
| Storage | SQLite |
| Frontend | React with Vite |
| Charts | Recharts |
| Testing | Pytest |
| Orchestration | Docker Compose |

These choices are fixed for V1. Rationale and trade-offs are documented in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 4. Packet-Ingestion Progression

Packet ingestion is introduced in four controlled stages. Each stage feeds the **same** downstream detection pipeline, so detectors and storage never need to know how an event was produced.

1. **Deterministic synthetic events** — clearly labelled, used only for automated tests and early demonstrations.
2. **Controlled PCAP replay** — the first *real* packet-ingestion method; packets are generated locally and replayed into the pipeline.
3. **Controlled live capture** — from the isolated Docker lab, via a sidecar sensor sharing the victim's network namespace.
4. **Suricata integration** — a later professional-tooling phase (post-V1).

Every event is tagged with a `source_type` of `synthetic`, `replay` or `live`, and the dashboard displays an unmissable banner reflecting it, so demonstration traffic can never be mistaken for real capture.

---

## 5. Version 1 In-Scope Features

### 5.1 Backend

- FastAPI application with a health endpoint.
- Typed packet-event and alert schemas (see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)).
- A common detector interface plus two detectors: a **TCP port-scan detector** and a **suspicious SYN-activity detector** (see [DETECTION_RULES.md](DETECTION_RULES.md)).
- Configurable thresholds and time windows, with per-key detector-state expiry.
- Alert cooldown and deduplication with well-defined update semantics.
- SQLite alert storage with pre-aggregated traffic statistics.
- REST endpoints for alerts and statistics, plus an authenticated ingest endpoint.
- WebSocket broadcasting of live alert deltas.
- Unit, integration and end-to-end tests.

### 5.2 Frontend

- Overview statistics.
- Live alert feed and a filterable, sortable alert table.
- Traffic timeline and protocol-distribution charts (Recharts).
- Alert-detail view exposing evidence, confidence and severity.
- A clear, persistent traffic-source indicator (SYNTHETIC / REPLAYED / LIVE-LAB).
- An optional AI-explanation section (populated only when the AI layer is enabled).

### 5.3 Controlled Laboratory

- A private Docker network with the victim service isolated from the host.
- An Nginx victim service, never published to the host.
- A safe traffic generator.
- Three scenarios: normal traffic, port scan, and SYN burst.
- PCAP replay support.
- No publicly exposed victim services.

### 5.4 Optional AI Explanation Layer (later phase)

An optional AI Security Analyst that **explains existing alerts** — it never detects attacks, never creates or suppresses alerts, and receives only sanitised, structured metadata. The complete application must function fully with the AI layer disabled and no API key present. Full design in [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md).

---

## 6. Explicit Version 1 Exclusions

The following are deliberately **out of scope** for V1. They are recorded here so reviewers understand the boundaries and can distinguish scoping decisions from omissions.

| Excluded | Reason |
| --- | --- |
| UDP-scan detection | V1 detectors focus on TCP reconnaissance and SYN abuse. UDP scanning is a candidate for a later phase. |
| Distributed / multi-source scan correlation | V1 detectors key on a single source (port scan) or single destination (SYN flood); correlating many sources is future work. |
| Cross-detector deduplication | Port-scan and SYN-activity alerts may both fire on the same burst. This is intentional; see [DETECTION_RULES.md](DETECTION_RULES.md). |
| User authentication / multi-user access | The dashboard is a single-operator lab tool bound to loopback. No account system in V1. |
| Cloud or internet deployment | The lab is isolated and internal-only. Production deployment is post-V1. |
| Deep packet / payload inspection | By design. Only metadata is processed; there is no payload field in the event schema. |
| IPv6-targeted detection | IPv6 packets are normalised and safely handled, but the V1 detectors are specified against IPv4 lab traffic. |
| Signature or machine-learning detection | V1 uses transparent heuristics only. Signature-based tooling arrives with Suricata (post-V1). |

---

## 7. Ethics and Authorised-Use Restrictions

This project exists to demonstrate **defensive** capability. The following constraints are absolute:

- Use is limited to education, research and **authorised** laboratory environments.
- The system must never target third-party systems or any system without explicit authorisation.
- The project must never contain offensive malware, persistence mechanisms, credential-theft functionality, or capabilities intended to evade detection for malicious purposes.
- The traffic generator produces only benign, laboratory-scoped traffic against the project's own victim container; it is not a general-purpose attack tool.
- Operators are responsible for ensuring their use complies with all applicable laws and organisational policies.

Security requirements that enforce these principles technically are detailed in [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md).

---

## 8. Project Limitations

Stated plainly so the project is not oversold:

- **Heuristic, not authoritative.** Detection is based on transparent thresholds, not signatures or trained models. Confidence is expressed as heuristic strength (capped at 0.95), never as certainty.
- **Laboratory-scale.** Thresholds, throughput expectations and the SQLite single-writer storage model are sized for an isolated lab, not production traffic volumes.
- **Victim-centric visibility.** Live capture observes traffic to and from the victim only (a consequence of the sidecar design in [NETWORK_DESIGN.md](NETWORK_DESIGN.md)); traffic between other hosts is out of scope.
- **Initial thresholds are lab defaults.** All detector thresholds are configurable starting points for the lab, not universal security standards or tuned production values.
- **Not a production IDS.** Professional-grade detection (Suricata) and hardened deployment are explicitly deferred to post-V1 phases described in [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md).

---

## 9. Open Decisions

- **Licence.** The repository's `LICENSE` file is currently empty. Licence selection is recorded as an open Phase 0/0.5 decision, with the **MIT Licence** recommended for approval (permissive, widely understood, portfolio-friendly, compatible with all planned dependencies). To be resolved in Phase 0.5. See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md).
- **Lab subnet.** The lab network uses `172.28.0.0/24` by default, overridable via configuration; a pre-flight collision check is documented in [NETWORK_DESIGN.md](NETWORK_DESIGN.md).
