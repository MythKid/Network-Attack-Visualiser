# API Reference

**Document status:** Implemented in Phase 3. This document is the authoritative contract for the backend's REST endpoints and the WebSocket alert feed. Interactive OpenAPI documentation is served at `/docs` on a running backend.

**Related documents:** [ARCHITECTURE.md](ARCHITECTURE.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [DETECTION_RULES.md](DETECTION_RULES.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), [TESTING_STRATEGY.md](TESTING_STRATEGY.md).

---

## 1. Conventions and semantics that apply everywhere

### 1.1 Timestamps are logical event time

Every timestamp in an alert (`created_at`, `last_seen`, `window_start`, `window_end`) and in statistics (`bucket_ts`) is **canonical logical event time**, derived from `PacketEvent.ts` — **never** the server's wall clock. Synthetic and replayed traffic carry deliberately controlled timestamps (the built-in synthetic scenarios use small epoch values, i.e. 1970-era dates), so:

- Values from different `source_type`s are **different timelines, not different instants**. A live alert's `created_at` (~1.7e9) being numerically larger than a synthetic alert's (~1000) says nothing about which was recorded first.
- Clients must render these values as *event* time and must **never** present them relative to the wall clock ("3 minutes ago") for non-live sources.
- This is what makes accelerated PCAP replay produce byte-identical alerts to real-time replay (see [DETECTION_RULES.md](DETECTION_RULES.md) §2.1).

### 1.2 Ordering is recording order

Where "newest first" appears below, it means **order of recording** (database insertion order), not event time. Across mixed `source_type`s no shared event timeline exists, so recording order is the only honest merged feed. A client that wants one coherent event-time series filters by `source_type`.

### 1.3 CORS

REST responses apply an exact browser-origin allowlist (`CORS_ALLOW_ORIGINS`, default `http://localhost:5173,http://127.0.0.1:5173`): an allowed `Origin` receives that exact origin back (never `*`, never credentials); a disallowed `Origin` receives no CORS headers. Only `GET` is offered to browsers — the ingest endpoint is a server-to-server boundary, not a browser one. WebSocket upgrades are validated separately (§5).

---

## 2. `GET /health`

Liveness and version check. Returns `200` with:

```json
{ "status": "ok", "version": "0.3.0" }
```

---

## 3. Alerts

### 3.1 `GET /api/v1/alerts`

One page of alerts, newest-recorded first, plus the total matching the same filters.

| Query parameter | Type | Default | Constraints |
| --- | --- | --- | --- |
| `severity` | enum | – | `low \| medium \| high \| critical` |
| `detector_id` | enum | – | `portscan \| synflood` |
| `source_type` | enum | – | `synthetic \| replay \| live` |
| `category` | enum | – | `reconnaissance \| dos` |
| `limit` | int | `50` | `1..200` |
| `offset` | int | `0` | `>= 0` |

An unrecognised enum value is a `422`, not an empty result.

```json
{
  "items": [ /* full Alert objects, see ALERT_SCHEMA.md §2 */ ],
  "total": 12,
  "limit": 50,
  "offset": 0
}
```

**Consistency.** `items` and `total` in one response are mutually consistent (they are read under a single database session). **Offset pagination is deterministic per query but not snapshot-stable across separate requests:** ingest committing between two page requests can shift rows across page boundaries, so a paging client may see an alert twice or watch `total` change. The dashboard's model — load a REST snapshot, then apply WebSocket deltas — already tolerates this.

**Reads can briefly wait behind ingest.** All database access is serialised through one connection; a read issued while an ingest batch is committing waits for that batch's write phase. Reads are *not* concurrent with writes in this phase (see [ARCHITECTURE.md](ARCHITECTURE.md) §5.4).

### 3.2 `GET /api/v1/alerts/{alert_id}`

The full alert record. `alert_id` must be a UUIDv4 (`422` otherwise); an unknown or pruned id is a `404`.

### 3.3 Alert update semantics worth knowing as a consumer

- **`occurrence_count` / `last_seen`** grow as an alert is reinforced within its cooldown; `created_at` never changes.
- **`window_start` is the start of the whole episode**, while `evidence.window_start` describes the *latest* burst — so `alert.window_start <= alert.evidence["window_start"]` is normal on a reinforced alert, not a bug.
- **`severity` only escalates** on updates (never auto-lowers, to avoid flapping). **`confidence` refreshes to the latest value** and may tick down — it is derived from the (refreshed) evidence, and a stale confidence beside fresh evidence would be incoherent.
- The `dedup_key` is an identity, not a uniqueness constraint: after a detector's cooldown elapses, the same hosts produce a **new** alert row.

---

## 4. Statistics — `GET /api/v1/stats`

One internally consistent snapshot: every section is read under a single database session, so `sum(alerts_by_severity) == totals.alert_count` always holds within one response.

| Query parameter | Type | Default | Constraints |
| --- | --- | --- | --- |
| `buckets` | int | `300` | `1..3600` — most recent distinct **logical event-time seconds** for the timeline |
| `source_type` | enum | – | `synthetic \| replay \| live`; scopes **every** section |

```json
{
  "totals": {
    "alert_count": 3,
    "alert_occurrence_total": 7,
    "event_count": 1200,
    "byte_count": 76800
  },
  "alerts_by_severity":    { "low": 0, "medium": 2, "high": 1, "critical": 0 },
  "alerts_by_detector":    { "portscan": 2, "synflood": 1 },
  "alerts_by_source_type": { "synthetic": 3, "replay": 0, "live": 0 },
  "protocol_distribution": [
    { "protocol": "TCP", "packet_count": 1150, "byte_count": 73600 }
  ],
  "traffic_timeline": [
    { "bucket_ts": 1000.0, "protocol": "TCP", "source_type": "synthetic",
      "packet_count": 5, "byte_count": 320 }
  ]
}
```

**Counting semantics.**

| Field | Counts |
| --- | --- |
| `alert_count` | Alert **rows** — distinct alerts, not reinforcements. |
| `alert_occurrence_total` | Total triggers **including** reinforcements (`SUM(occurrence_count)`); always `>= alert_count`. "3 alerts" and "7 triggers" are different facts — a dashboard must not label one as the other. |
| `alerts_by_*` | Rows, consistent with `alert_count`; **every known key is present** with an explicit `0`, so clients need no defaulting. |
| `event_count` / `byte_count` | Sums over **all retained** statistics buckets (whole history), scoped by `source_type` when given. |

**Timeline selection is provenance-aware.** `buckets` counts the most recent distinct one-second buckets **independently per `source_type`**, then merges. A global "latest N seconds" would let live timestamps (~1.7e9) crowd every synthetic and replay bucket (~1000) out of the chart entirely (§1.1). One second holds at most one row per `(protocol, source_type)` — 4 × 3 = 12 rows — so an unfiltered response carries at most `buckets × 12` timeline rows.

**Scope note.** `totals` and `protocol_distribution` cover the whole retained history ("what has this lab seen"); `traffic_timeline` covers the recent window ("what happened lately"). They deliberately do not share the `buckets` parameter.

---

## 5. WebSocket — `WS /api/v1/ws/alerts`

Live **deltas only**; alert history is fetched over REST on page load ([ALERT_SCHEMA.md](ALERT_SCHEMA.md) §5). Connecting never replays anything, so reconnects cause no replay storms.

**Handshake.** The `Origin` header is validated against the same allowlist as CORS (middleware does not cover upgrades) and a mismatched or missing origin is refused **before** the socket is accepted — close code `1008`, an HTTP `403` on the wire.

**Messages** (server → client only):

```json
{ "type": "alert.created", "alert": { /* full Alert */ } }
{ "type": "alert.updated", "alert": { /* full Alert */ } }
```

The client reconciles deltas against its REST snapshot, keyed by `alert_id`.

**Slow consumers are disconnected, not silently skipped.** Each subscriber has a bounded queue (`WS_MAX_QUEUE`, default 100). A consumer that falls behind is closed with code **`1013` (Try Again Later)**: the correct client response is to reconnect and re-load the REST snapshot. Skipping deltas instead would silently desynchronise the client's view with no way to notice — REST is authoritative; deltas are best-effort by design.

**Client → server messages are ignored.** The channel is one-directional; a stray frame (for example an application-level keepalive) is logged and dropped, never fatal.

---

## 6. Ingest — `POST /api/v1/ingest/events`

The sensor→backend boundary. Browsers never call this endpoint.

**Authentication.** Every request must carry the shared secret in `X-Sensor-Token`, compared in constant time. When no `SENSOR_TOKEN` is configured the endpoint **fails closed** with `503` — there is no default token.

**Request** (1..`INGEST_MAX_BATCH` events; whole-batch validation — nothing is partially ingested):

```json
{ "events": [ /* PacketEvent objects, see ALERT_SCHEMA.md §1 */ ] }
```

**Response** — `202 Accepted`:

```json
{ "accepted": 200, "alerts_created": 1, "alerts_updated": 0 }
```

- `accepted` is the number of events taken into the pipeline (the whole validated batch). Events individual detectors ignore or drop as too-late still count — they were accepted and included in traffic statistics.
- `alerts_created` / `alerts_updated` count only deltas whose rows **survive same-batch row-cap pruning** (`ALERT_MAX_ROWS`): an alert created and pruned within one batch has no external existence — never counted, never broadcast, absent from REST.

**Error responses:**

| Code | Cause |
| --- | --- |
| `401` | Missing or incorrect `X-Sensor-Token`. |
| `413` | Request body over `INGEST_MAX_BODY_BYTES` (checked before parsing — declared *and* actual size), or batch over `INGEST_MAX_BATCH`. |
| `422` | Malformed or partially invalid batch (nothing ingested); empty batch; unknown body fields; a live event skewed beyond `MAX_CLOCK_SKEW_S` from server time. Synthetic/replay events are exempt from the skew check — their timestamps are deliberately controlled. |
| `500` | Storage failure **before commit** — the batch rolled back. |
| `503` | `SENSOR_TOKEN` not configured. |

**Enforcement order** — the first two checks run in pure-ASGI middleware **before FastAPI reads or parses the body** (FastAPI decodes the body ahead of route dependencies, so a dependency-based token check could not guarantee this order; a route-level dependency is retained purely as defence in depth):

1. declared `Content-Length` above the cap → `413` (nothing read);
2. sensor token → `503` (unconfigured, fail closed) or `401` (missing/incorrect) — an unauthenticated caller never receives a body-parse verdict, even for malformed JSON;
3. actual received bytes counted against the cap while the body streams → `413` (catches chunked and dishonestly-declared bodies);
4. JSON/schema validation of the whole batch → `422`;
5. batch cap → `413`;
6. live clock-skew check → `422`.

The batch cap cannot precede parsing (counting events requires parsing), and the body cap already bounds parse cost, so a batch that is both oversized-in-count and malformed yields `422`, not `413`. All checks run before any event reaches a detector.

### 6.1 Retry contract — read this before writing a sensor

**Ingest is non-idempotent and retry-unsafe.**

- Events are consumed by stateful detectors the moment they are processed; they are never persisted, so the backend cannot deduplicate a resend.
- **After a `500`:** the batch's rows and statistics were rolled back, but detector windows already consumed the events. Re-sending the identical batch distorts detector state (double-counted SYNs, inflated windows) and cannot recover the lost alert.
- **After a timeout:** the commit may well have succeeded and only the response was lost. Re-sending then **double-counts traffic statistics** and distorts detector windows.
- Therefore: **do not blindly retry a failed or timed-out ingest POST.** A deliberate sensor-side policy is future (Phase 6) work and must be designed against this contract.
- **A committed batch never turns into an error because something after the commit failed:** WebSocket publication problems and internal cleanup failures (e.g. the cooldown-gate sweep) after commit are logged server-side and the `202` is still returned. Dashboards recover through REST, which is authoritative.

---

## 7. Environment variables (Phase 3)

All documented in `.env.example`. `SENSOR_TOKEN` is the only secret and has no default.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_PATH` | `data/nav.sqlite3` | SQLite database path (`:memory:` accepted). Ephemeral lab data; git-ignored. |
| `CORS_ALLOW_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Exact browser-origin allowlist (comma-separated; wildcards rejected on load). |
| `SENSOR_TOKEN` | *(none)* | Shared ingest secret, min 16 chars. Unset ⇒ ingest returns `503`. |
| `INGEST_MAX_BATCH` | `200` | Max events per ingest request. |
| `INGEST_MAX_BODY_BYTES` | `262144` | Max ingest body size, enforced before parsing. |
| `MAX_CLOCK_SKEW_S` | `300` | Max \|live `ts` − wall clock\| accepted. |
| `ALERT_MAX_ROWS` | `10000` | Rolling cap on stored alert rows (oldest-recorded pruned). |
| `WS_MAX_QUEUE` | `100` | Per-subscriber WebSocket queue bound; overflow ⇒ close `1013`. |

---

## 8. Known limitations (Phase 3)

- **Reads serialise behind writes.** One shared SQLite connection; a read issued mid-commit waits for that batch's write phase. WAL's concurrent-reader benefit requires separate reader connections and is not realised yet ([ARCHITECTURE.md](ARCHITECTURE.md) §5.4).
- **`event_stats` is unbounded.** Time-based retention (`ALERT_RETENTION_DAYS`, `STATS_RETENTION_HOURS`) is deferred; only the alert row cap is enforced. The database is ephemeral lab data and can be deleted freely.
- **The dedup/cooldown gate is in-memory.** A backend restart inside a cooldown window produces a new alert row on the next trigger rather than reinforcing the pre-restart row.
- **Alert delivery is not exactly-once.** A storage failure after detector mutation loses those candidates permanently (§6.1); a WebSocket delta can be lost on overflow or disconnect, recovered via REST re-sync.
