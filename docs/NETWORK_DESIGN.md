# Network Design

**Document status:** Design, with the environment verified and the first ingestion stage implemented. **The network lab and packet-capture architecture described here are not implemented.** What exists today: the agreed development environment (§1) — Docker Desktop with WSL 2 integration on Ubuntu-26.04 — has been verified; and stage 1 of the ingestion progression in §11, the **in-process synthetic events** of Phase 2, is implemented (it involves no network, no bridge and no capture). **Planned for Phases 5 and 6:** the Docker lab topology (§2), the port publication model (§3), bridge capture mechanics and capture visibility (§4–§7), self-capture filtering (§8), PCAP replay (§11 stage 2) and live capture (§11 stage 3). See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) and [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) for current status.

**Related documents:** [PROJECT_SCOPE.md](PROJECT_SCOPE.md), [ARCHITECTURE.md](ARCHITECTURE.md), [DETECTION_RULES.md](DETECTION_RULES.md), [ALERT_SCHEMA.md](ALERT_SCHEMA.md), [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md), [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md).

This is the most important design document in the set. It analyses, carefully, *why a sensor container attached to a Docker bridge cannot simply observe all traffic between other containers*, and specifies the topology, addressing, capture strategy and privilege model that follow from that analysis.

---

## 1. Agreed Development Environment

The agreed and verified environment is **Docker Desktop with WSL 2 integration on Ubuntu-26.04**:

- Docker Desktop's WSL 2 integration is enabled and confirmed working inside the `Ubuntu-26.04` distribution (`docker run --rm hello-world` succeeds inside WSL).
- The `docker-desktop` utility distribution runs alongside `Ubuntu-26.04` under WSL 2.
- **No second, native Docker Engine will be installed inside Ubuntu.** This is settled, not an open question.

This environment has a direct consequence for packet capture: Docker's bridge interfaces (`docker0`, `br-<id>`) do not live in the Ubuntu distribution's network namespace. They live inside the hidden `docker-desktop` utility VM. Therefore `ip link` and `tcpdump` run inside Ubuntu **cannot see** the Docker bridges, and Wireshark on Windows cannot see intra-lab traffic either. Section 9 covers this in full. The capture design in this document is deliberately chosen so that it never depends on host-side bridge access, which makes it behave identically regardless of these WSL 2 specifics.

---

## 2. Network Topology

Version 1 uses two Docker bridge networks:

- **`lab_net`** — the isolated laboratory segment. `internal: true` (no route to the host or the internet), subnet `172.28.0.0/24` (overridable via `LAB_SUBNET`; see the collision check in Section 2.2). Static addresses:
  - **victim** — `172.28.0.10` (Nginx, unprivileged image). No published ports.
  - **generator** — `172.28.0.20` (safe traffic generator).
  - **backend (lab interface)** — `172.28.0.30`. **This address belongs only to the backend's `lab_net` interface.**
- **`app_net`** — the management/presentation segment. Bridge network with default addressing. Members: **backend** and **frontend**. Containers on `app_net` address one another by **Docker service-name DNS** (for example `http://backend:8000`); there are **no static IPs** on `app_net`.

The **sensor** does not attach to either network directly. It shares the victim's network namespace via `network_mode: "service:victim"` (Section 7).

```
        app_net (bridge, service-name DNS)          lab_net (bridge, internal: true, 172.28.0.0/24)
   ┌──────────┐                                             │
   │ frontend │───────────────┐                            ├── .10 ── victim (nginx-unprivileged, no ports)
   │  (nginx) │               │                            │            ▲ shared network namespace
   └────┬─────┘               │        ┌──────────┐        │         ┌──┴───────────────────────────┐
127.0.0.1:5173:8080           ├────────│ backend  │── .30 ─┤         │ sensor                       │
   (browser)                  │        │ (FastAPI)│        │         │ network_mode:"service:victim"│
                              │        └────┬─────┘        │         │ Scapy sniff on eth0          │
                   127.0.0.1:8000:8000      │              │         └──────────────────────────────┘
                    (browser REST/WS)       │ POST /api/v1/ingest/events
                                            └──────────────┤
                                                           ├── .20 ── generator (Scapy scenarios)
```

Note that the backend is **dual-homed**: it sits on `app_net` (reachable from the frontend by service name) and on `lab_net` (reachable from the sensor at `172.28.0.30`). The reasoning behind this shape is in Sections 6 and 7.

### 2.1 Why static addresses on `lab_net`
Static lab addresses are not cosmetic. The self-capture exclusion filter (Section 8) references the backend's lab address `172.28.0.30` literally, so that address must be stable. The victim and generator are also fixed so scenarios and documentation can refer to them unambiguously.

### 2.2 Subnet collision pre-flight
Before `docker compose up`, confirm `172.28.0.0/24` is free, because Docker Desktop manages its own address pools and a collision would prevent the network being created:

```
docker network ls
docker network inspect $(docker network ls -q) | grep -i subnet
```

If the subnet is in use, override it via `LAB_SUBNET` (and update the static addresses accordingly). This check is documented so a first run on an unfamiliar machine does not fail confusingly.

---

## 3. Port Publication Model

Only the two operator-facing services publish ports, and both bind to loopback only. Nothing else is published; the victim is never reachable from the host.

| Service | Internal listen | Published mapping | Reachable from |
| --- | --- | --- | --- |
| backend | `0.0.0.0:8000` | `127.0.0.1:8000:8000` | Host loopback only (published); `app_net` + `lab_net` internally |
| frontend | `0.0.0.0:8080` (nginx-unprivileged) | `127.0.0.1:5173:8080` | Host loopback only |
| victim | `80` | **none** | `lab_net` only |
| sensor | n/a | **none** (cannot publish; shares victim namespace) | n/a |
| generator | n/a | **none** | `lab_net` only |

The backend process listens **inside its container on `0.0.0.0:8000`** so it is reachable through **both** `app_net` (frontend, by service name) and `lab_net` (sensor, at `172.28.0.30`). This container-internal `0.0.0.0` bind is **not** host exposure: the only way onto the host is the **loopback-restricted published mapping** `127.0.0.1:8000:8000`. In short, **no published host port binds to `0.0.0.0`** — the internal listener and the host mapping are different things. The frontend container's Nginx listens **internally on port 8080**; `5173` is only the host-side published port (kept familiar because it is Vite's default dev port). Nginx does not listen on 5173.

**Browser access model:** the operator opens the dashboard at `http://localhost:5173`. Browser-side JavaScript calls the backend through its host-published address, `http://localhost:8000` (REST) and `ws://localhost:8000/api/v1/ws/alerts` (WebSocket). These are **cross-origin** calls, governed by an exact CORS allowlist and explicit WebSocket `Origin` validation (see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §4.2). Container-to-container calls (frontend or sensor to backend) use Docker service names or the lab static address as appropriate — never the browser's `localhost`.

Loopback binding under Docker Desktop is discussed in Section 9.

---

## 4. The Docker Traffic-Visibility Problem

**A naive assumption to avoid:** "attach a third 'sensor' container to the same Docker network as the victim and generator, put its interface in promiscuous mode, and it will see all the lab traffic." This is incorrect, and understanding *why* is central to the design.

A Docker bridge network is implemented as a **Linux bridge**, which behaves like a **learning switch**, not a hub:

- The bridge maintains a **forwarding database (FDB)** mapping MAC addresses to bridge ports (each container's `veth`).
- When a frame arrives, the bridge learns the source MAC → ingress port, then forwards the frame **only** to the port associated with the destination MAC.
- A third container therefore receives only: frames addressed to **its own** MAC, **broadcast** frames (for example ARP), **multicast** frames, and **unknown-unicast** frames that are flooded because the destination MAC is not yet in the FDB.
- Putting the sensor's `veth` in **promiscuous mode does not help**: promiscuous mode affects what the *interface* accepts, but the *bridge* still only delivers the frames above to that port. There is nothing extra to accept.

### 4.1 The unknown-unicast trap
This is the subtle failure that makes naive sensors look like they work. Before the bridge has learned a destination MAC — and again after the FDB entry ages out (the Linux bridge default ageing time is roughly **300 seconds** of silence) — unicast frames to that destination are **flooded to all ports**, including the sensor's. So a quick test appears to succeed for the first packets of a conversation, then the sensor goes **silently blind** once the FDB learns the real destination port. A design that relies on this would be unreliable and, worse, *intermittently* unreliable — the hardest kind of fault to trust in a portfolio piece.

**Conclusion:** a sensor on the shared bridge cannot reliably observe unicast traffic between the victim and the generator. A different mechanism is required.

---

## 5. Capture Options Considered

| # | Option | Verdict | Why |
| --- | --- | --- | --- |
| a | Sensor on the shared bridge (promiscuous) | **Rejected** | Learning-switch behaviour and the unknown-unicast trap (Section 4). Intermittent, unreliable. |
| b | Host-side capture on `br-<id>` | **Rejected** | Under Docker Desktop the bridge lives inside the `docker-desktop` utility VM, unreachable from Ubuntu; the approach is engine-dependent and non-portable. |
| c | Set bridge FDB `ageing_time 0` (turn the switch into a hub) | **Rejected** | Requires host/root access to the bridge, which is unreachable under Docker Desktop; also abuses the bridge and does not generalise. |
| d | `tc` / `mirred` port mirroring | **Rejected** | Brittle, requires host access, and is disproportionate complexity for a lab. |
| e | **PCAP replay into the pipeline** | **Chosen — first real ingestion** | No visibility problem at all: packets are generated locally and fed directly to the detection pipeline. Fully reproducible from a clean clone. |
| f | **Sidecar sharing the victim's network namespace** | **Chosen — live capture (Phase 6)** | The sensor sees *all* traffic to and from the victim, needs only `CAP_NET_RAW`, and behaves identically under both Docker engine placements because it never touches the host bridge. |

Options (e) and (f) are the V1 progression: replay first (Phase 5), live sidecar later (Phase 6). Option (f)'s scope is *victim-centric* — the sensor sees traffic to and from the victim, which is exactly the V1 threat model; traffic between other hosts is out of scope and is documented as a limitation in [PROJECT_SCOPE.md](PROJECT_SCOPE.md).

Considering and rejecting (a)–(d) explicitly is deliberate: the reasoning is precisely the networking knowledge this project is meant to demonstrate.

---

## 6. The Compose Constraint and the Dual-Homed Backend

The chosen live-capture option (Section 5f) shares the victim's namespace:

```yaml
sensor:
  network_mode: "service:victim"   # shares the victim's network namespace
```

Docker Compose forbids a service that uses `network_mode: "service:<name>"` from also declaring its own `networks:` or `ports:`. The sensor therefore **cannot** sit on a separate management network and **cannot** publish anything. So how do captured events reach the backend?

**Resolution — dual-homed backend.** The backend is attached to both networks:

- `app_net` — so the frontend can reach it by service name, and its API can be published to the host.
- `lab_net` at `172.28.0.30` — so the sensor (which lives in the victim's namespace on `lab_net`) can POST events to it.

The sensor ships events to `http://172.28.0.30:8000/api/v1/ingest/events`. The `172.28.0.30` address is the backend's **`lab_net` interface only**; on `app_net` the backend is addressed by service name.

**Alternatives rejected:** a dedicated sensor↔backend network is impossible under the `network_mode` constraint; running the backend inside the victim's namespace would couple API availability to the lab and is rejected; running the sensor as a host process abandons containerisation and reintroduces engine-specific behaviour.

**Honest trade-off:** because the backend has a foot in `lab_net`, its ingest traffic exists on the lab segment and is therefore in the path the sensor sniffs. That is exactly the feedback-loop risk addressed in Section 8. The victim and generator never initiate connections to the backend, so the only backend-related lab traffic is the sensor↔backend ingest connection, which the filter in Section 8 removes.

---

## 7. Sensor Capture Mechanics and Least Privilege

The sensor runs Scapy inside the victim's network namespace and sniffs the victim's `eth0`. Because the namespace is shared, **every frame to or from the victim is already delivered to that interface** — there is no need for promiscuous mode:

- Sniff with `promisc=False` (Scapy: `sniff(iface="eth0", promisc=False, filter=...)`, `conf.sniff_promisc = False`).
- Setting an interface promiscuous requires `CAP_NET_ADMIN`; **not** using promiscuous mode means the sensor needs only `CAP_NET_RAW` (to open the `AF_PACKET` raw socket). This is a real least-privilege win.

The sensor normalises each frame to a `PacketEvent` (metadata only — no payload; see [ALERT_SCHEMA.md](ALERT_SCHEMA.md)), batches events, and POSTs them to the backend. Batching flushes at **200 events or 0.5 seconds**, whichever comes first. Each POST carries an `X-Sensor-Token` shared secret (from the environment) so the generator cannot inject fake telemetry (see [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)).

---

## 8. Self-Capture Feedback Loop and Its Control

Because the backend is on `lab_net` (Section 6), the sensor's own ingest POSTs — **and the backend's HTTP responses back to the sensor** — traverse the very interface the sensor is sniffing. Left unfiltered this creates a self-amplifying loop: each captured packet becomes an event, each event becomes an HTTP POST, whose packets are captured, and so on. The backend's response packets would also be captured needlessly.

The loop is a **transport-level** problem: it forms at the moment a packet is captured and turned into a network POST, long before any application-layer logic runs. This has a decisive consequence for where the loop can actually be broken, and the three layers below are ordered by that reasoning. Two of the three layers (primary and secondary) prevent the loop from forming; the third cannot, and its role is deliberately narrower.

### 8.1 Layer 1 — Primary: kernel BPF exclusion (bidirectional)
The sensor installs a BPF capture filter **on the `AF_PACKET` socket in the kernel**, so the excluded frames are dropped before they are ever delivered to the sensor's userspace at all. The filter excludes **both directions** of the sensor↔backend HTTP connection — the request to `172.28.0.30:8000` and the response from `172.28.0.30:8000` — while still capturing TCP, UDP, ICMP and all other unrelated traffic. The **explicit form is the documented form**, for clarity:

```
not (
  (dst host 172.28.0.30 and tcp dst port 8000) or
  (src host 172.28.0.30 and tcp src port 8000)
)
```

The compact equivalent is noted but is *not* the primary documented form:

```
not (host 172.28.0.30 and tcp port 8000)
```

This excludes only the sensor↔backend ingest connection in both directions. Any other traffic to or from `172.28.0.30` — anything that is not TCP, or not port 8000 — continues to be captured. Because the backend never runs any other service on the lab segment, this filter removes exactly the ingest connection and nothing else. This is the layer that actually prevents the feedback loop: an excluded frame never reaches userspace, so it can never become an event or a POST.

### 8.2 Layer 2 — Secondary: sensor-side userspace filter
Immediately after the sensor parses a frame, and **before it constructs a `PacketEvent` or enqueues anything into a batch**, it applies the same bidirectional match in userspace and discards self-traffic:

```
protocol == TCP
  AND (
        (dst_ip == 172.28.0.30 AND dst_port == 8000)
     OR (src_ip == 172.28.0.30 AND src_port == 8000)
  )
```

This is a defence-in-depth backstop for the primary layer: if the kernel BPF filter were ever missing, mistyped, or unsupported on a given capture path, the userspace filter still stops self-traffic before an event is created or a POST is generated — so it, too, prevents the loop from forming. Placement matters: it must run **before** `PacketEvent` creation and batch enqueueing, because that is the last point at which discarding the packet also prevents the network POST.

### 8.3 Layer 3 — Tertiary: backend event filter (cannot break the transport loop)
As a final layer, the backend drops any *ingested* event that matches the ingest connection in **either** direction:

```
protocol == TCP
  AND (
        (dst_ip == 172.28.0.30 AND dst_port == 8000)
     OR (src_ip == 172.28.0.30 AND src_port == 8000)
  )
```

It does **not** drop every event whose source or destination is `172.28.0.30`. All other (non-8000 / non-TCP) traffic to or from the backend is left untouched.

**What this layer can and cannot do.** It prevents self-traffic from entering **statistics and detection**, so even a leaked self-event never pollutes `event_stats` or triggers a spurious alert. But it **cannot by itself prevent the transport-level feedback loop.** By the time the backend rejects an event, the sensor has *already* captured the packet and *already* generated another HTTP POST; rejecting the event server-side does nothing to un-send that POST or to stop the next capture. Breaking the loop is therefore the job of Layers 1 and 2 (which act before a POST exists); Layer 3 only guarantees that any self-traffic which nonetheless reaches the backend is excluded from analysis. The earlier draft's claim that this backend filter alone means "the loop cannot form" was incorrect and is corrected here.

---

## 9. WSL 2 and Docker Traffic-Visibility Risks

The environment (Section 1) shapes what is and is not observable:

| Concern | Behaviour under Docker Desktop + WSL 2 |
| --- | --- |
| Where the Docker bridges live | Inside the hidden `docker-desktop` utility VM. Not visible to `ip link` / `tcpdump` in the `Ubuntu-26.04` distro, and not visible to Windows. |
| Can host `tcpdump`/Wireshark see lab traffic? | **No.** Ubuntu-side `tcpdump` cannot see the bridge; Windows Wireshark sees only the Hyper-V vNIC / NAT egress, and the lab is `internal: true` so there is no egress to see. The only escape hatch is a privileged container run inside the utility VM (`docker run --rm --net=host --privileged nicolaka/netshoot tcpdump -i br-<id>`) — a documented *debugging* trick, never part of the architecture. |
| Published loopback ports | Docker Desktop forwards `127.0.0.1:8000` and `127.0.0.1:5173` to the Windows loopback, so a Windows browser can reach `http://localhost:5173` and `http://localhost:8000`. |
| Address pools | Docker Desktop manages its own default address pool; hence the subnet collision pre-flight in Section 2.2. |

**Why the sidecar design is robust to all of this:** the sensor never touches the host or the bridge. It captures inside the victim's namespace, which exists regardless of where the engine runs. This engine-independence — not merely the reduced privilege — is the decisive argument for the sidecar approach.

---

## 10. Container Privilege and Linux Capability Considerations

No container runs as `privileged: true`. Every service sets `no-new-privileges: true`, drops all capabilities by default, runs as a non-root user where practical, pins its image version, and defines a health check. Full policy in [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md).

| Service | User | Capabilities | Networks | Published ports |
| --- | --- | --- | --- | --- |
| frontend | non-root (`nginx-unprivileged`) | `cap_drop: [ALL]` | `app_net` | `127.0.0.1:5173:8080` |
| backend | non-root (`USER app`) | `cap_drop: [ALL]` | `app_net` + `lab_net` (`172.28.0.30`) | `127.0.0.1:8000:8000` |
| victim | non-root (`nginx-unprivileged`) | `cap_drop: [ALL]`; read-only filesystem where practical | `lab_net` (`172.28.0.10`) | none |
| sensor | non-root (preferred) | `cap_drop: [ALL]`, `cap_add: [NET_RAW]` | `network_mode: "service:victim"` | none |
| generator | non-root | `cap_drop: [ALL]`, `cap_add: [NET_RAW]` (Scapy SYN crafting; the normal-traffic scenario needs no capabilities) | `lab_net` (`172.28.0.20`) | none |

### 10.1 The non-root + `NET_RAW` gotcha
A commonly missed Linux detail: a **non-root** process cannot use a capability that is merely added with `cap_add`. The capability must reach the process through **file** or **ambient** capabilities. So a sensor that runs as a non-root `USER` with `cap_add: [NET_RAW]` will, by default, still be denied the raw socket.

**Why file capabilities on the interpreter are *not* the settled answer.** A tempting fix is `setcap cap_net_raw+eip` on the Python interpreter in the sensor image, so a non-root process picks up the capability on exec. **This conflicts directly with the mandatory `no-new-privileges: true` policy** (Section 10, [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) §3). Setting `no_new_privs` tells the kernel that an `execve` must **not** grant the process any privilege it did not already have, and the kernel therefore **ignores file capabilities during exec** (the file's permitted/effective bits are not applied). Ambient capabilities are the deliberate exception the kernel still honours under `no_new_privs`, precisely because they are already held by the calling process rather than granted by the executable. Consequently, `setcap` on the interpreter and `no-new-privileges: true` are mutually exclusive, and the earlier "recommended for portfolio polish" framing of the `setcap` approach was wrong. We do **not** relax `no-new-privileges` to make `setcap` work.

**Phase 6 decision: an executable capability test, not a paper choice.** The exact mechanism is resolved when the sensor image is actually built and run in Phase 6, by inspecting the live process capability sets (see below). Only these two candidates are acceptable, and whichever is adopted must be *proven* to work:

1. **Verified non-root ambient-capability configuration.** Raise `NET_RAW` into the process's **ambient** set (for example via a minimal entrypoint that calls `PR_CAP_AMBIENT_RAISE`, with `NET_RAW` present in the permitted and inheritable sets), keeping `USER` non-root and `no-new-privileges: true` intact. This is preferred *if* it is demonstrably working on the built image; it is not assumed to work without the test.
2. **Narrowly scoped root-in-container fallback.** Run the sensor as root **inside the container only**, with `cap_drop: [ALL]`, `cap_add: [NET_RAW]`, `no-new-privileges: true`, **no** `privileged` mode, a read-only root filesystem where practical, and no unnecessary capabilities. Documented as a deliberate, tightly scoped exception, acceptable if candidate (1) cannot be verified.

**Acceptance is by inspection, not assertion.** Phase 6 acceptance must read the *actual* process capability sets (for example `CapEff`/`CapPrm`/`CapBnd`/`CapAmb` from `/proc/<pid>/status`, cross-checked with `getpcaps`/`capsh --decode`) and prove that raw-socket capture works with **only `NET_RAW`** effective — no broader capability set, no `privileged`. The same consideration, and the same test, applies to the generator's Scapy SYN crafting.

---

## 11. Packet Capture and Replay Strategy

The four-stage ingestion progression (see [PROJECT_SCOPE.md](PROJECT_SCOPE.md)) maps onto the network design as follows:

1. **Synthetic events** (Phase 2) — in-process, no network involved; clearly labelled `source_type: synthetic`.
2. **PCAP replay** (Phase 5) — the first real ingestion. PCAPs are **generated locally** by a committed script (`scripts/generate_pcaps.py`) using Scapy's `wrpcap`. Crafting and writing PCAP files needs **no privileges** (only sending/sniffing does), so generation runs unprivileged from a clean clone. PCAPs are **never committed** (the repository `.gitignore` blocks `*.pcap`, `*.pcapng`, `*.cap`) and are **never downloaded from external links**, so there are no dead links and the replay path is fully reproducible. Replayed events carry `source_type: replay`. **Event-time preservation:** replay uses each packet's **captured timestamp** as the event's canonical logical time; acceleration may reduce or remove the wall-clock sleeps between packets but must **not** compress the detection windows or change which alerts fire — an accelerated replay and a real-time replay of the same PCAP are alert-identical (see [DETECTION_RULES.md](DETECTION_RULES.md) §2.1).
3. **Live capture** (Phase 6) — the sidecar sensor described above; `source_type: live`.
4. **Suricata** (post-V1) — an `eve.json` ingester behind the same interfaces (see [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md)).

Ingest authentication (`X-Sensor-Token`) and the batching parameters (200 events / 0.5 s) apply to the live path; synthetic and replay ingestion run in-process and do not cross the network.

---

## 12. Known Network Limitations

- **Victim-centric only.** Live capture observes traffic to and from the victim; other host-to-host lab traffic is not seen.
- **Single lab segment.** V1 models one victim, one generator and one sensor. Multi-victim or segmented-lab topologies are future work.
- **No host-side capture.** By design and by environment, the system never depends on capturing at the Docker bridge; this rules out observing traffic that never reaches the victim's namespace.
- **Subnet assumption.** `172.28.0.0/24` is assumed free; the pre-flight check (Section 2.2) and `LAB_SUBNET` override exist because that assumption can fail on a busy Docker host.
