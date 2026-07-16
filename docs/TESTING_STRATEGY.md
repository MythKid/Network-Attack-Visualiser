# Testing Strategy

**Document status:** Partially implemented. The testing philosophy (§1), the deterministic clock-injection harness (§2) and the Phase 2 unit-test coverage (§3 — schema and configuration validation, detector threshold boundaries, the SYN handshake state machine, state-creation gates, window/expiry mechanics and cross-`source_type` isolation), together with the synthetic-event and detection-engine tests, are **implemented**. Everything mapped to a later phase in §13 remains **planned**: the cooldown/deduplication tests (§4), the malformed-packet corpus and replay end-to-end (§5, §8), integration and WebSocket tests (§6, §7), frontend tests (§9), Docker verification (§10), AI-layer tests (§11) and the coverage gate (§12). See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) for current status.

**Related documents:** [ARCHITECTURE.md](ARCHITECTURE.md), [DETECTION_RULES.md](DETECTION_RULES.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [NETWORK_DESIGN.md](NETWORK_DESIGN.md), [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md), [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md).

---

## 1. Testing Philosophy

- **Determinism first.** The most important testability decision is that detectors take an injected clock and perform no I/O. Time-dependent behaviour (windows, state TTL, cooldown) is therefore tested by advancing a fake clock to exact boundaries, with no reliance on wall-clock timing or `sleep`.
- **Test the contract, not the internals.** Tests target the detector interface, the ingest→alert→storage→API path, and the WebSocket contract.
- **Nothing claimed to work until tested.** A phase is complete only when its acceptance criteria (see [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md)) pass.
- **No live externalities in tests.** No real network, no real AI provider; the AI layer is exercised through a mock provider.

The framework is **Pytest** for the backend and **Vitest + React Testing Library** for the frontend, with an optional Playwright smoke test.

---

## 2. Deterministic Clock Injection (foundational)

Detectors never call `time.time()`. `update(event, now)` and `expire(source_type, now)` receive **one canonical logical event time** derived from `PacketEvent.ts` (see [DETECTION_RULES.md](DETECTION_RULES.md) §2.1). `expire` names the `source_type` its `now` belongs to because each provenance partition runs on its own logical clock; tests can therefore drive one partition's expiry directly and assert that the others do not move. Tests use a `FakeClock` that advances by exact amounts to cross time boundaries. The Phase 2 tests use this deterministic clock harness for the sliding-window and TTL boundaries; Phase 3 will reuse the **same** harness for cooldown boundaries:

- Cross a sliding-window edge to prove old events fall out of the window (Phase 2).
- Cross a state-TTL boundary to prove idle keys are pruned by `expire` (Phase 2).
- Cross a cooldown boundary to prove the update-vs-new-row transition (Section 4) — **Phase 3**, with the Alert Engine that owns cooldown timing.

An injected clock must be **tested as injected**: `expire(source_type, now)` is exercised **directly** (not only via `update`) at the exact TTL boundary and just beyond it, which is what proves the supplied logical time is honoured rather than quietly ignored in favour of internal state.

**Event-time semantics** ([DETECTION_RULES.md](DETECTION_RULES.md) §2.1):
- Feeding events whose `ts` is preserved (not wall-clock) proves accelerated PCAP replay and live capture produce **identical** detector behaviour — the same alerts fire regardless of replay speed.
- A mildly out-of-order event lands in its correct window and does **not** rewind the logical high-water mark (so it cannot prematurely trigger `expire`); a too-late event (`ts` before the window start) is dropped and counted, not folded into a closed window.
- An unreasonable timestamp (non-finite, or beyond the configured live skew bound `MAX_CLOCK_SKEW_S`) is rejected before it reaches a detector.

---

## 3. Unit Tests (Phase 2 onward)

**Schema validation** ([ALERT_SCHEMA.md](ALERT_SCHEMA.md)):
- Valid `PacketEvent` accepted; invalid enum values, out-of-range ports, and missing required fields rejected.
- `CandidateAlert` construction validates severity enum and the confidence range (0–0.95) and carries **no** identity/dedup/AI fields (those belong to `Alert`).
- `Alert` construction validates severity/`ai_status` enums and the confidence range (0–0.95).
- **Non-finite JSON rejected recursively:** `NaN` and `±Infinity` in `evidence` or `threshold_snapshot` are rejected on **both** `CandidateAlert` and `Alert`, at the top level and inside nested dictionaries and lists. This is tested explicitly because the permissive default is silent: Pydantic's `JsonValue` accepts non-finite floats and serialises them to `null`, destroying the evidence instead of refusing it.

**Configuration validation** ([DETECTION_RULES.md](DETECTION_RULES.md) §8):
- Non-finite windows, TTLs, cooldowns and ratios are rejected in `PortScanConfig`, `SynFloodConfig` and `DetectionSettings` — including from environment variables, since `float()` parses `"inf"` and `"nan"` happily.
- The `DetectionEngine` rejects a non-finite `max_window_s` and a non-finite detector-derived `max_event_age_s`.

**Detector threshold boundaries** ([DETECTION_RULES.md](DETECTION_RULES.md)):
- `portscan`: `PORTSCAN_MIN_PORTS − 1` distinct ports → no alert; `PORTSCAN_MIN_PORTS` → alert. Severity band boundaries (medium/high/critical at 15/30/100 with defaults) verified.
- `synflood`: below `SYN_MIN_COUNT` → no alert; at/above with `completion_ratio < SYN_MAX_COMPLETION_RATIO` → alert. Severity bands (medium/high/critical) verified.

**SYN handshake state machine and completion accounting** ([DETECTION_RULES.md](DETECTION_RULES.md) §4.1–§4.2):
- Retransmitted SYN does not double-count `syn_count`.
- SYN-ACK for a missed SYN creates a `SYN_ACK_SEEN` entry with `syn_observed = False` and does **not** increment `syn_count`.
- **Orphan SYN-ACK followed by a final ACK** (no SYN ever observed) removes the entry and adds **no** `completed_handshake` — the completion never enters the numerator.
- **Missed SYN-ACK with an observed SYN**, then a final ACK, **does** count a completion (out-of-order/lost SYN-ACK tolerated only when the SYN was seen).
- **Ratio bounds:** across mixed sequences (orphans, retransmissions, completions), `0.0 ≤ completion_ratio ≤ 1.0` always holds and `completed_handshakes ≤ syn_count`.
- **Window expiry of the cohort:** once an attempt's observed SYN ages out of `SYN_WINDOW_S`, it leaves both numerator and denominator together, and a pending entry with no progress expires after `HANDSHAKE_TTL_S` without adding a completion.
- Bare ACK with no pending entry is ignored; RST removes an entry without a completion.
- **SYN-ACK progression vs evidence:** a SYN-ACK inside `HANDSHAKE_TTL_S` but outside `SYN_WINDOW_S` may progress pending state, yet leaves `synack_count` unchanged and never appears in candidate evidence (§4.2).
- **Cross-`source_type` isolation:** interleaving `synthetic` and `live` SYNs for the same `dst_ip` keeps two independent cohorts and never merges counts (§6).

**No state without cause** ([DETECTION_RULES.md](DETECTION_RULES.md) §2). Each of these must leave the detector with **no** key state, and must not refresh an existing key's idle TTL — otherwise ignored traffic leaks memory and keeps dead keys alive:
- A SYN older than `SYN_WINDOW_S` creates no key, pending entry or cohort attempt.
- A SYN-ACK / final ACK / RST older than `HANDSHAKE_TTL_S` creates no key or pending entry.
- A bare ACK creates no target key.
- An unmatched RST creates no target key.

**Window / expiry mechanics:**
- Events sliding out of the window stop contributing.
- `expire(source_type, now)` frees idle-key state in **that** partition after the configured TTL: state is retained at the exact TTL boundary and removed just beyond it.
- Expiring one `source_type` neither advances nor removes another's state — proven in both directions (`live` must not expire `synthetic`, and vice versa).

**Cooldown semantics** (Section 4) — Phase 3, with the Alert Engine that owns cooldown timing.

---

## 4. Cooldown / Deduplication Tests (Phase 3)

Directly exercise the update-vs-new-row behaviour from [DETECTION_RULES.md](DETECTION_RULES.md):

- Two triggers for the same `dedup_key` **within** cooldown → **one** alert row, `occurrence_count == 2`, `last_seen` and `window_end` advanced, one `alert.created` then one `alert.updated` broadcast.
- Severity on update may escalate upward but never auto-lowers.
- A trigger **after** cooldown → a **second** alert row (`alert.created`), proving the dedup key never permanently suppresses future alerts.

---

## 5. Malformed-Packet Corpus Tests (Phase 5)

A corpus/fuzz test feeds the replay ingester adversarial input to satisfy the networking-robustness requirement:

- Truncated frames and short reads.
- Non-IP frames (for example ARP-only).
- IPv6 packets.
- Unexpected or unknown L4 protocols.
- Missing L4 headers.

Expectation: no exceptions escape; each frame is either dropped or normalised to a valid `PacketEvent` with `protocol` = `OTHER`. The parser never crashes the ingester.

---

## 6. Integration Tests (Phase 3)

Using FastAPI's `TestClient` against a temporary-file or in-memory SQLite database:

- Authenticated `POST /api/v1/ingest/events` batch → detection → SQLite row → visible via `GET /api/v1/alerts`.
- Ingest with a missing/incorrect `X-Sensor-Token` is rejected; the token is compared in constant time (`hmac.compare_digest`).
- **Ingest limits** (see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §5.1): a batch exceeding `INGEST_MAX_BATCH` (200) is rejected; an over-size request body is rejected before parsing; a malformed/partially-invalid batch is rejected (422) with **nothing** partially ingested; a live event with timestamp skew beyond `MAX_CLOCK_SKEW_S` (and a non-finite `ts`) is rejected.
- **CORS / WebSocket origin** (see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §4.2): an allowed `Origin` receives the exact allow headers with no wildcard and no credentials; a disallowed `Origin` receives no allow headers and is refused the WebSocket upgrade.
- `GET /api/v1/alerts` filtering/pagination, `GET /api/v1/alerts/{id}`, and `GET /api/v1/stats` return correct data.
- The tertiary backend event filter removes only the ingest connection in both directions and leaves other traffic intact, keeping self-traffic out of statistics and detection (see [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §8.3). This test asserts containment only; it does not assert loop-breaking, which belongs to the BPF and userspace filters (§10).

---

## 7. WebSocket Tests (Phase 3)

Using `TestClient.websocket_connect`:

- A newly ingested alert is pushed as `alert.created`.
- A reinforcement within cooldown is pushed as `alert.updated`.
- On connect, the socket does **not** replay history (history comes from REST), so there is no reconnect "replay storm".
- Reconnection behaves gracefully.

---

## 8. Replay End-to-End (Phase 5)

Fully deterministic because the input is a fixed, locally generated PCAP:

- `generate_pcaps.py` → port-scan PCAP → replay ingester → assert the expected `portscan` alert and its evidence.
- Likewise for the SYN-burst PCAP → `synflood`.
- **Acceleration invariance:** replaying the same PCAP at real-time speed and at an accelerated speed yields **identical** alerts, because detection runs on the preserved capture timestamps, not wall-clock delivery time (see [DETECTION_RULES.md](DETECTION_RULES.md) §2.1, [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §11).

---

## 9. Frontend Tests (Phase 4)

- **Vitest + React Testing Library** component tests for the alert table/feed and, importantly, the traffic-source banner logic (SYNTHETIC / REPLAYED / LIVE-LAB driven by `source_type`).
- Empty and error states render sensibly.
- **Optional Playwright smoke test** loads the dashboard against a seeded backend.

---

## 10. Docker Verification (Phase 6)

- From Phase 6 onward (once `docker-compose.yml` exists) CI runs `docker compose config` to validate the Compose file, and `docker compose build` for image sanity — both **mandatory** here, having been merely conditional before Phase 6 (see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §11, [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) Phase 0.5).
- A scenario-driven check (run locally / on a self-hosted runner, since Docker Desktop in hosted CI is awkward) runs the port-scan scenario and asserts an alert appears via the API.
- Audits confirm non-root users (`docker inspect`), dropped capabilities, absence of `privileged`, health checks present, and only the two loopback ports published.
- The self-capture control is verified at **both** enforcing layers ([NETWORK_DESIGN.md](NETWORK_DESIGN.md) §8): (a) the kernel BPF exclusion filter, and (b) the sensor-side userspace filter applied before `PacketEvent` creation / batch enqueueing. Each independently keeps the sensor↔backend ingest connection out of the event stream so no feedback loop forms. The tertiary backend event filter is tested separately as a containment measure (§6): it keeps any leaked self-traffic out of statistics and detection but is **not** relied on to break the transport loop.

---

## 11. AI-Layer Tests (Phase 7)

All using a **mock provider** — no live network:

- The sanitiser drops every non-allowlisted field; raw IPs never appear in the summary sent to a provider (see [AI_EXPLANATION_DESIGN.md](AI_EXPLANATION_DESIGN.md)).
- Timeout → deterministic fallback (`ai_status = "fallback"`).
- Rate-limit exceeded → fallback, not an error.
- Cache hit returns without calling the provider.
- Disabled mode returns deterministic templated text and the app remains fully functional.
- **Input limits** (§6.1): a serialised `AlertSummary` over `AI_MAX_INPUT_CHARS`, or `evidence_summary` over `AI_MAX_EVIDENCE_FIELDS`, falls back and the mock provider is **never called**.
- **Output validation** (§6.1): an over-`AI_MAX_OUTPUT_CHARS`, empty, whitespace-only, or schema-invalid mock response → fallback; the invalid text is never persisted.
- **Safe rendering:** explanation text containing raw HTML/script is escaped or stripped — no unsanitised markup reaches the rendered output.
- **Retry discipline:** a transient failure (timeout / `5xx` / `429`) is retried up to `AI_MAX_RETRIES` then falls back; an ordinary `4xx` is **not** retried and falls back immediately.

---

## 12. Coverage Gate (Phase 8)

- **≥ 85%** line coverage on backend `detection/`, `alerts/`, and `models/` — the correctness-critical modules.
- Coverage is a floor, not a target to game; deliberately untested areas (for example thin glue code) are noted rather than padded with trivial tests.

---

## 13. Test-Category-to-Phase Map

| Test category | Introduced in |
| --- | --- |
| Clock-injection harness, schema, configuration, detection-engine and detector unit tests | Phase 2 |
| Alert lifecycle, cooldown and deduplication tests | Phase 3 |
| Integration and WebSocket tests | Phase 3 |
| Frontend component tests | Phase 4 |
| Malformed-packet corpus, replay e2e | Phase 5 |
| Docker verification | Phase 6 |
| AI-layer (mock-provider) tests | Phase 7 |
| Coverage gate | Phase 8 |

This mapping is consistent with the acceptance criteria in [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md).
