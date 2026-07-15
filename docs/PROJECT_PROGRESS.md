# Project Progress

**Last updated:** 2026-07-15

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

---

## Current Phase

**Phase 0.5 — Tooling and CI Baseline: complete.** Phase 0 (design documentation) is committed and pushed.

No application code, application dependencies, containers or services exist yet. This is by design: development proceeds one approved phase at a time. The next approved unit of work is Phase 1 (backend skeleton).

---

## Remaining Work

| Phase | Title | Status |
| --- | --- | --- |
| 0.5 | Tooling and CI baseline (Ruff, mypy, Pytest config, pre-commit, GitHub Actions); resolve licence | **Complete** |
| 1 | Backend skeleton (FastAPI, health endpoint, config) | Planned (next) |
| 2 | Detection engine + synthetic events | Planned |
| 3 | Alert pipeline (SQLite storage, dedup/cooldown, REST, WebSocket) | Planned |
| 4 | Frontend dashboard | Planned |
| 5 | PCAP replay + Scapy hardening | Planned |
| 6 | Docker lab + live sidecar capture | Planned |
| 7 | AI explanation layer | Planned |
| 8 | Hardening and polish | Planned |
| Post-V1 | Suricata integration; hardened deployment | Future |

Acceptance criteria for each phase are in [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md).

---

## Known Issues and Open Decisions

- **Licence (resolved 2026-07-15).** Resolved in Phase 0.5: the project is licensed under the **MIT License** (`LICENSE`, Copyright (c) 2026 Methindu Damsara), referenced from the README. No longer an open decision.
- **Lab subnet collision check.** The lab uses `172.28.0.0/24` by default (overridable via `LAB_SUBNET`). A pre-flight collision check must be run before `docker compose up`; procedure documented in [NETWORK_DESIGN.md](NETWORK_DESIGN.md).
- **Sensor `NET_RAW` capability approach.** `setcap cap_net_raw+eip` on the Python interpreter is **ruled out** because it conflicts with the mandatory `no-new-privileges: true` policy (the kernel ignores file capabilities on `execve` under `no_new_privs`). The mechanism is resolved by an **executable capability test in Phase 6** between exactly two candidates: (1) a verified non-root **ambient-capability** configuration (preferred if proven on the built image), or (2) a narrowly scoped **root-in-container** fallback (`cap_drop: [ALL]`, `cap_add: [NET_RAW]`, `no-new-privileges: true`, no `privileged`). Acceptance inspects the actual process capability sets. Full analysis in [NETWORK_DESIGN.md](NETWORK_DESIGN.md) §10.1.

**Not an open decision:** the container runtime is settled — **Docker Desktop with WSL 2 integration on Ubuntu-26.04**, enabled and verified. No native Docker Engine will be installed in Ubuntu.

---

## Next Milestone

**Phase 1 — Backend Skeleton** (a minimal, running FastAPI application with configuration and a health endpoint). See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md). Not started; awaits explicit approval.
