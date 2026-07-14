# AI Explanation Layer Design

**Document status:** Phase 0 design. Nothing described here is implemented yet, and **no AI provider or SDK will be added until the AI phase (Phase 7) is approved.** This document defines the agreed architecture so a provider can be selected at that time.

**Related documents:** [PROJECT_SCOPE.md](PROJECT_SCOPE.md), [ARCHITECTURE.md](ARCHITECTURE.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md).

---

## 1. Goals and Non-Goals

The optional AI Security Analyst **explains existing alerts** in plain language. The deterministic detection engine remains authoritative.

**The AI may:**
- Explain, in plain language, what happened and why a detector triggered.
- Summarise the supporting evidence.
- Describe what the severity and confidence mean.
- Explain possible false positives and known limitations.
- Recommend defensive investigation or response steps.

**The AI must never** (hard prohibitions, restated from the project rules):
- Create alerts independently.
- Suppress alerts.
- Change or automatically re-grade alert severity.
- Execute commands.
- Control the attack simulator / traffic generator.
- Modify detection thresholds.
- Receive full packet payloads.
- Receive passwords, cookies, tokens, credentials or secrets.
- Present uncertain analysis as confirmed fact.

The complete application must function fully with the AI **disabled** and **no API key present**.

---

## 2. Architectural Placement

AI code lives in its own module (`backend/app/ai/`), separate from detection, API and storage logic. The rest of the system depends only on a small interface, never on any provider. The layer is disabled by default and, when enabled, is invoked *after* an alert already exists — it is an annotation step, never part of the detection or alert-lifecycle path.

---

## 3. Provider Abstraction

A provider-independent abstraction keeps the project uncoupled from any single company and supports hosted, future-local and disabled modes.

```python
from typing import Protocol, Literal
from pydantic import BaseModel

class AlertSummary(BaseModel):
    """The ONLY data a provider ever receives — sanitised, allowlisted, no IPs."""
    detector_id: str
    detector_version: str
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float
    protocol: str | None
    src_role: str | None          # e.g. "lab-generator" — never a raw IP
    dst_role: str | None          # e.g. "lab-victim"     — never a raw IP
    evidence_summary: dict        # numeric/enum evidence only (see §4)
    threshold_snapshot: dict
    window_duration_s: float

class Explanation(BaseModel):
    text: str
    source: Literal["ai", "fallback"]
    provider: str | None
    model: str | None
    generated_at: float

class ExplanationProvider(Protocol):
    name: str
    async def explain(self, summary: AlertSummary, *, timeout_s: float) -> Explanation: ...
    async def healthy(self) -> bool: ...
```

**Implementations:**
- `DisabledProvider` — the **default**. Returns the deterministic fallback; makes no external call.
- `TemplateFallbackProvider` — deterministic sentence templates per detector and severity. Always available, always offline; this is what guarantees the app works with no AI.
- `HostedHTTPProvider` (Phase 7) — a provider-independent HTTP client. **No specific vendor or SDK is chosen here.**
- A future **local provider** mode fits the same interface (for on-device or self-hosted models).

---

## 4. Sanitisation (allowlist, not blocklist)

Sanitisation is an **allowlist**: only explicitly permitted fields are assembled into the `AlertSummary`; everything else is dropped by construction. Using an allowlist (rather than trying to strip forbidden fields) means a newly added alert field cannot leak by default.

**Permitted to leave the process:**
- `detector_id`, `detector_version`, `category`, `severity`, `confidence`, `protocol`.
- Numeric evidence only — fields matching `*_count`, `*_ratio`, `*_rate`, `distinct_*`.
- `threshold_snapshot`.
- Window duration.
- Roles: `src_role` / `dst_role` (or salted hashes), **never** raw IPs.

**Never permitted:** raw IP addresses, any free-text or host-identifying strings, TCP flag strings, and of course anything payload- or credential-derived (which does not exist in the schema anyway; see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)).

The sanitiser is a **pure function** with dedicated unit tests proving that non-allowlisted fields cannot appear in an `AlertSummary` and that raw IPs never leave (see [TESTING_STRATEGY.md](TESTING_STRATEGY.md)).

---

## 5. Orchestration

A single `ExplanationService` orchestrates a request in this fixed order:

```
cache lookup ──hit──► return cached explanation
     │ miss
     ▼
rate-limit check ──over limit──► deterministic fallback
     │ ok
     ▼
provider.explain(summary, timeout_s)  (with retries)
     │            │
   success      failure / timeout / error
     │            │
     ▼            ▼
 cache + persist   deterministic fallback
```

- **Fallback is never an application error.** Any failure — disabled, timeout, rate-limited, provider error — yields a deterministic templated explanation. The dashboard always has something useful to show.
- Generated text is persisted on the alert row (`ai_explanation`), so re-rendering is free and does not re-call the provider.

### 5.1 `ai_status` lifecycle
Recorded on each alert (see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)):

```
none ──► generated   (AI produced the explanation)
     └─► fallback    (deterministic template used)
     └─► error       (unexpected failure; fallback text still shown)
```

Explanations are **always clearly labelled** as AI-generated or as the deterministic fallback, so an operator never mistakes an AI narrative for authoritative fact.

---

## 6. Controls

All configured via environment variables:

| Control | Variable | Default | Behaviour |
| --- | --- | --- | --- |
| Timeout | `AI_TIMEOUT_S` | `8` | Exceeded → fallback. |
| Retries | `AI_MAX_RETRIES` | `1` | With backoff; **transient failures only** (see §6.1); then fallback. |
| Rate limit | `AI_MAX_CALLS_PER_MIN` | (set per provider) | Token bucket; over-limit → fallback. |
| Max input size | `AI_MAX_INPUT_CHARS` | `4000` | Serialised `AlertSummary` above this → fallback (never sent). |
| Max evidence fields | `AI_MAX_EVIDENCE_FIELDS` | `24` | `evidence_summary` above this many keys → fallback. |
| Max output size | `AI_MAX_OUTPUT_CHARS` | `2000` | Provider response is truncated/rejected above this (see §6.1). |
| Cache | (LRU + TTL) | — | Keyed by `(detector_id, severity, coarse-bucketed evidence)`; identical alert shapes reuse one explanation. |
| Mode | `AI_PROVIDER` | `disabled` | `disabled` / hosted / (future) local. |

### 6.1 Input and output validation

The provider boundary is validated on **both** sides; any breach yields the deterministic fallback, never an application error or unsafe render.

**Input (before any external call):**
- **Maximum serialised `AlertSummary` size** — `AI_MAX_INPUT_CHARS`. If the serialised summary exceeds it, the request falls back and is **never sent**.
- **Maximum evidence fields** — `AI_MAX_EVIDENCE_FIELDS` caps the number of keys in `evidence_summary` (defence-in-depth on top of the §4 allowlist), bounding prompt size and blast radius.
- The summary is still built by the §4 allowlist, so these caps are size limits on an already-sanitised object, never a substitute for sanitisation.

**Output (before persisting or rendering):**
- **Maximum response size** — `AI_MAX_OUTPUT_CHARS` (or the provider's token equivalent). A response over the limit is rejected → fallback.
- **Response schema validation** — the provider reply must parse into the expected `Explanation` shape; anything else is treated as failure → fallback.
- **Empty or malformed responses** — an empty, whitespace-only, or unparseable response is a failure → fallback (never stored as an explanation).
- **Safe rendering** — explanation text is treated as **plain text / restricted Markdown** and rendered with **no unsanitised HTML**: any raw HTML is escaped or stripped, so a provider response can never inject markup or script into the dashboard.

**Retry discipline:**
- Retries (`AI_MAX_RETRIES`) apply **only to transient failures** — timeouts, connection errors, and provider `5xx`/`429`.
- **Ordinary `4xx` errors are not retried** (they will not succeed on repeat); they go straight to fallback.

---

## 7. Provider-Selection Criteria

No vendor is chosen now; the choice is made in Phase 7 against these criteria:

- **Privacy / data-training terms** — does the provider train on submitted data? Prefer providers that do not.
- **Cost model and rate limits** — understood and bounded. **No external API is assumed to be permanently free**; free tiers and pricing can change.
- **Latency** — comfortably within the timeout budget.
- **Plain HTTP API** — usable without a heavy, coupling SDK, consistent with the provider-independent HTTP interface.
- **Self-hostable / local option** — availability of a local or self-hosted model for the future local mode.
- **Licence / Terms of Service** — compatible with an open-source portfolio project.
- **Determinism controls** — supports low/zero temperature for stable, reproducible explanations.
- **Maturity and maintenance** — actively maintained, stable API.

---

## 8. Guarantee

The AI explanation layer is strictly additive. With `AI_PROVIDER=disabled` (the default) and no API key, every feature of the Network Attack Visualiser works, alerts are fully explained by the deterministic fallback, and no external call is ever made. Enabling AI only enriches the explanation text; it changes nothing about detection, alerts, storage or control.
