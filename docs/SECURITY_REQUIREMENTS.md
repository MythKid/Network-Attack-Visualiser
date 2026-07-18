# Security Requirements

**Document status:** Partially implemented; this document defines the agreed Version 1 security posture in full. **Implemented through Phase 2:** loopback-default backend configuration; validated application configuration and typed domain inputs; the metadata-only `PacketEvent` schema with no payload field (§7); finite-value validation for timestamps, evidence, threshold snapshots, detector configuration and engine horizons; `source_type`-separated detector state; ignored and age-gated packets being prevented from creating or refreshing detector state; and the repository ignore rules for secrets, packet captures, local databases and generated artifacts (§8). **Implemented in Phase 3:** authenticated ingest with constant-time token comparison and fail-closed behaviour when unconfigured (§5); the ingest body-size, batch, schema-first and clock-skew limits (§5.1); the exact browser CORS allowlist with credentials disabled and the independent WebSocket `Origin` validation (§4.2); the `SENSOR_TOKEN` secret handled as a non-printable secret type and documented only as a placeholder (§6); and database file permissions restricted to the owning user. **Planned for later phases:** container and Linux capability hardening (§3); isolated Docker networking (§4); bridge capture and self-capture controls (the tertiary backend event filter of §4.1 arrives with the Phase 6 lab that defines its addresses); time-based retention; and the AI-provider security controls (§10). See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) for current status.

**Related documents:** [PROJECT_SCOPE.md](PROJECT_SCOPE.md), [NETWORK_DESIGN.md](NETWORK_DESIGN.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md).

---

## 1. Defensive-Only Mandate

This is a **defensive** project. The following are prohibited without exception:

- Offensive malware of any kind.
- Persistence mechanisms.
- Credential theft or harvesting.
- Targeting of third-party systems, or any system without explicit authorisation.
- Detection-evasion techniques intended for malicious use.

The traffic generator produces only benign, laboratory-scoped traffic against the project's own victim container. It is not, and must not become, a general-purpose attack tool.

---

## 2. Ethics and Authorised-Use Restrictions

Use is restricted to **education, research and authorised laboratory environments**. The lab network is isolated (`internal: true`) and never exposes the victim to the host or the internet. Operators are responsible for legal and organisational compliance. These principles are stated in [PROJECT_SCOPE.md](PROJECT_SCOPE.md); this document defines how they are enforced technically.

---

## 3. Container Security Requirements

No container runs privileged. The complete matrix (also in [NETWORK_DESIGN.md](NETWORK_DESIGN.md)):

| Service | User | Capabilities | Notes |
| --- | --- | --- | --- |
| frontend | non-root (`nginx-unprivileged`) | `cap_drop: [ALL]` | Serves built static assets on internal port 8080. |
| backend | non-root (`USER app`) | `cap_drop: [ALL]` | Dual-homed (`app_net` + `lab_net` `172.28.0.30`). |
| victim | non-root (`nginx-unprivileged`) | `cap_drop: [ALL]` | Read-only filesystem where practical; no published ports. |
| sensor | non-root (preferred) | `cap_drop: [ALL]`, `cap_add: [NET_RAW]` | Shares victim namespace; needs only `NET_RAW`. |
| generator | non-root | `cap_drop: [ALL]`, `cap_add: [NET_RAW]` | `NET_RAW` only for SYN crafting; normal traffic needs none. |

Mandatory for every service:

- **No `privileged: true`** anywhere.
- **`no-new-privileges: true`** on every service.
- **`cap_drop: [ALL]`**, then add back only what is strictly required.
- **Non-root users** wherever practical.
- **Pinned image versions** (ideally by digest), never `latest`.
- **Health checks** on every long-running service.
- **Minimal images** and, where appropriate, multi-stage builds.

### 3.1 The non-root + `NET_RAW` capability detail
A non-root process cannot use `NET_RAW` merely because Compose lists `cap_add: [NET_RAW]`; the capability must arrive via **file** or **ambient** capabilities. Crucially, **file capabilities via `setcap cap_net_raw+eip` on the Python interpreter are ruled out by the mandatory `no-new-privileges: true` policy**: `no_new_privs` makes the kernel ignore file capabilities on `execve`, so `setcap` and `no-new-privileges` cannot both hold. We keep `no-new-privileges: true` and do **not** rely on interpreter file capabilities.

The mechanism is therefore resolved by an **executable capability test in Phase 6**, choosing between exactly two acceptable candidates: (1) a **verified non-root ambient-capability** configuration (preferred, if proven on the built image), or (2) a **narrowly scoped root-in-container fallback** (`cap_drop: [ALL]`, `cap_add: [NET_RAW]`, `no-new-privileges: true`, no `privileged`, read-only filesystem where practical, no unnecessary capabilities). Phase 6 acceptance inspects the **actual process capability sets** and proves raw-socket capture works with only `NET_RAW` effective. Full analysis in [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §10.1.

---

## 4. Network Exposure Policy

- **Loopback-published host ports only.** The two host-published mappings bind to `127.0.0.1` — backend `127.0.0.1:8000:8000`, frontend `127.0.0.1:5173:8080` — so **no published host port binds to `0.0.0.0`**. The backend *process* deliberately listens **inside its container on `0.0.0.0:8000`** so it is reachable through **both** `app_net` (by service name) and `lab_net` (at `172.28.0.30`, for the sensor). Container-internal `0.0.0.0` is not host exposure: only the loopback-restricted host mapping is reachable from the host, and `lab_net` is `internal: true`.
- **Victim never published.** The Nginx victim is reachable only on `lab_net`.
- **Lab is internal.** `lab_net` is `internal: true`: no route to the host or the internet.
- **Sensor cannot publish.** Sharing the victim's namespace, the sensor has no ports of its own.

| Service | Internal listen | Published | Reachable from |
| --- | --- | --- | --- |
| backend | 8000 | `127.0.0.1:8000:8000` | Host loopback only |
| frontend | 8080 | `127.0.0.1:5173:8080` | Host loopback only |
| victim | 80 | none | `lab_net` only |
| generator | n/a | none | `lab_net` only |

### 4.1 Self-capture feedback-loop control (defence in depth)

Because the backend is dual-homed onto `lab_net`, the sensor↔backend ingest connection traverses the interface the sensor sniffs. Left unfiltered this is a self-amplifying loop (each captured packet becomes an event, each event becomes a POST, whose packets are captured…) — a self-inflicted resource-exhaustion risk. Three ordered layers control it (full analysis in [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §8):

1. **Primary — kernel BPF exclusion.** A bidirectional BPF filter on the sensor's `AF_PACKET` socket drops both directions of the sensor↔backend connection before they reach userspace. This layer prevents the loop.
2. **Secondary — sensor-side userspace filter.** The sensor re-applies the same bidirectional match in userspace immediately after parsing and **before** `PacketEvent` creation or batch enqueueing, so a leaked frame still cannot become a POST. This layer also prevents the loop.
3. **Tertiary — backend event filter.** The backend drops matching ingested events so self-traffic never enters statistics or detection. This layer **cannot by itself break the transport loop** — by the time the backend rejects an event the sensor has already captured the packet and sent the POST — so it is a containment measure, not the loop-breaker.

### 4.2 Browser-facing CORS and WebSocket origin policy

Because the dashboard is served from `http://localhost:5173` while its JavaScript calls the backend directly at `http://localhost:8000` (REST) and `ws://localhost:8000/api/v1/ws/alerts` (WebSocket), these are **cross-origin** requests and must be governed by an explicit, minimal policy rather than a permissive default:

- **Exact REST CORS allowlist.** The backend allows **only** the dashboard origin(s) — `http://localhost:5173` and `http://127.0.0.1:5173` — configured via `CORS_ALLOW_ORIGINS` (comma-separated). **No wildcard (`*`)** origin. An unrecognised `Origin` receives no CORS-allow headers.
- **Credentials disabled.** `allow_credentials = false`: the browser never sends cookies or auth headers to the backend (the `X-Sensor-Token` boundary is server-side, sensor→backend, never browser→backend), so credentialed CORS is neither needed nor permitted. This also keeps a wildcard-plus-credentials misconfiguration impossible.
- **Only required methods and headers.** Allow just the methods the dashboard actually uses (`GET`, and `OPTIONS` for preflight) and only the request headers it sends (e.g. `Content-Type`). The browser never calls the ingest endpoint, so no write methods are exposed to it.
- **WebSocket `Origin` validation.** CORS middleware does **not** apply to WebSocket upgrades, so the backend independently validates the `Origin` header of the `WS /api/v1/ws/alerts` handshake against the same allowlist and **rejects** a mismatched or missing origin before accepting the socket.

This is verified in Phase 6/8 (see [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md), [TESTING_STRATEGY.md](TESTING_STRATEGY.md)): a disallowed `Origin` gets no CORS-allow headers on REST and is refused the WebSocket upgrade.

---

## 5. Ingest Authentication

The ingest endpoint (`POST /api/v1/ingest/events`) is reachable from `lab_net`, which also hosts the generator ("attacker"). To stop the generator injecting fabricated telemetry, every ingest request must carry a shared secret:

- Header **`X-Sensor-Token`**, value from the environment (`SENSOR_TOKEN`), never committed.
- The backend rejects any ingest request with a missing or incorrect token, comparing the token in **constant time** (`hmac.compare_digest`) so a timing side-channel cannot leak it.

This is an honest, minimal trust boundary appropriate to a lab: it authenticates the sensor to the backend without introducing a full auth system (which is out of V1 scope, see [PROJECT_SCOPE.md](PROJECT_SCOPE.md)).

### 5.1 Ingest limits and validation

Authentication alone is not enough: the ingest endpoint is on the same segment as the generator, so it must also be defensive about **shape and size**. The backend enforces, in this order, before any event reaches a detector:

- **Batch cap.** At most **`INGEST_MAX_BATCH` = 200** events per request (matching the sensor's flush size in [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §7); a larger batch is rejected (HTTP 413/422), not truncated.
- **Body-size cap.** A maximum request-body size (`INGEST_MAX_BODY_BYTES`, a small default such as 256 KiB) is enforced before parsing, so an oversized body is rejected (HTTP 413) rather than buffered.
- **Schema validation first.** Every event is validated against the `PacketEvent` schema **before** detector processing; a malformed or partially-invalid batch is rejected (HTTP 422) and never partially ingested.
- **Timestamp-skew rejection (live).** Live events whose `ts` is skewed beyond **`MAX_CLOCK_SKEW_S`** (default e.g. 300 s) from the backend's reference time — or is non-finite — are rejected as unreasonable before detection (see [DETECTION_RULES.md](DETECTION_RULES.md) §2.1). Synthetic and replay events carry deliberately controlled timestamps and are exempt from the wall-clock skew check.

These limits are covered by Phase 3 tests for oversized and malformed batches (see [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md), [TESTING_STRATEGY.md](TESTING_STRATEGY.md) §6).

---

## 6. Secrets Management

- **`.env` is never committed.** The repository `.gitignore` blocks `.env` and `.env.*` (except `.env.example`).
- **`.env.example`** ships with **placeholder** values only and documents every variable.
- **No secrets in images.** Secrets are never baked into Docker images or build args.
- **No secrets in logs.** Tokens and secrets are never written to logs or alert records.

---

## 7. Data Privacy Boundaries

Metadata only. The system **never** stores or logs:

- Packet payloads (the event schema has no payload field; see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)).
- Passwords, authentication tokens, cookies, or credentials.
- Full packet captures inside the database.

Retention limits (alerts: 7 days / 10 000 rows; `event_stats`: 24 hours) are defined in [ALERT_SCHEMA.md](ALERT_SCHEMA.md). The database is ephemeral, gitignored lab data.

---

## 8. Repository Safety

The repository `.gitignore` already blocks the sensitive and generated artefacts this project handles:

- Environment and secrets: `.env`, `.env.*`, `*.pem`, `*.key`, `credentials.json`, `secrets/`.
- Packet captures: `*.pcap`, `*.pcapng`, `*.cap`.
- Databases: `*.db`, `*.sqlite`, `*.sqlite3` and WAL side-files.
- Logs, runtime data, build output, `node_modules`, `__pycache__`.

Operational rules that follow:

- **PCAPs are generated locally** by `scripts/generate_pcaps.py` (Scapy `wrpcap`, unprivileged) and are **never committed** and **never downloaded from external links**.
- **Databases are generated at runtime** and are never committed.
- Only `.env.example` (placeholders) is committed for configuration.

---

## 9. Dependency Security

- Prefer mature, actively maintained libraries.
- **Pin versions** for reproducibility and supply-chain hygiene.
- Before adding a major dependency, document why it is needed, alternatives, licence, maintenance status, security considerations and performance impact (per the project's dependency policy).
- Do not install unnecessary packages. No AI provider or SDK is added until the AI phase is approved (see [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md)).

---

## 10. AI-Layer Security Constraints (summary)

The optional AI explanation layer is bound by strict constraints, summarised here and specified fully in [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md):

- Receives **only** sanitised, structured alert metadata drawn from an explicit **allowlist** (numeric and enumerated fields).
- **Never** receives raw payloads, IP-identifying data, credentials, cookies or tokens; raw IPs are replaced by roles or salted hashes before anything leaves the process.
- **Never** creates, suppresses or re-grades alerts; never executes commands; never controls the simulator; never modifies thresholds.
- Is **optional**: the complete application functions fully with the AI disabled and no API key present, always falling back to deterministic explanations.
- Explanations are always clearly labelled as AI-generated (or as the deterministic fallback).

---

## 11. Security Verification Expectations

Security is checked, not assumed (see [TESTING_STRATEGY.md](TESTING_STRATEGY.md)):

- CI runs `docker compose config` validation **conditionally** while no Compose file exists (before Phase 6), and **mandatorily** — together with image-build verification — from Phase 6 onward, once `docker-compose.yml` is introduced (see [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md)).
- Container audits confirm non-root users, dropped capabilities, absence of `privileged`, and that no published host port binds to `0.0.0.0` (only the two loopback mappings are published).
- The self-capture control is verified in Phase 6 by exercising **both** the kernel BPF filter **and** the sensor-side userspace filter (§4.1): the sensor↔backend ingest connection must produce no events and form no feedback loop.
- A secrets scan confirms no `.env`, keys, tokens or credentials are committed.
- The AI sanitiser has dedicated unit tests proving only allowlisted fields can leave the process.
