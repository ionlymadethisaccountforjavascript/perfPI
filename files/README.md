# IDLEBEACON

A mock application whose only job is to **look inactive while sending telemetry**, with
every knob exposed in a GUI and every action written to a ground-truth log.

It exists so you can answer, with known labels: *what does idle-state telemetry actually
look like in network flows, hardware counters and Windows performance counters, and how
faint can it get before we stop detecting it?*

It is a **signal generator and labelling instrument**, not a detector and not malware. It
talks only to a sink you run yourself, on a host and port you choose.

---

# PART A — HOW TO USE IT

## A.1 Contents

| File | Role |
|---|---|
| `idlebeacon.py` | The mock app: Tk GUI + engine + headless mode |
| `sink.py` | Minimal telemetry collector (TCP / UDP / HTTP), logs receipts |
| `collect_counters.ps1` | Windows per-process performance-counter sampler (1 Hz) |
| `profiles/*.json` | Preset configurations, including `silent_control.json` (the H₀ control) |

## A.2 Requirements

- Python 3.8+ (standard library only — no pip installs).
- Windows: Tk ships with the python.org installer. Nothing else needed.
- Linux: `sudo apt install python3-tk` if the GUI does not start.
- Headless mode needs no display at all.

## A.3 Quick start (single machine, 5 minutes)

Three terminals:

```bash
# 1. the sink (where telemetry goes)
python sink.py --port 5055 --logdir ./sink_logs

# 2. the mock app
python idlebeacon.py

# 3. Windows counters for the app's PID (shown in the app's title bar)
powershell -ExecutionPolicy Bypass -File .\collect_counters.ps1 -TargetPid 12345 -Out counters.csv
```

In the GUI: press the **mid** profile button, tick **Beacon ON**, then **Minimise (go S2)**
and leave the machine alone. Every beacon appears in the log pane, in
`idlebeacon_logs/events_*.jsonl`, and in the sink's receipt log.

> **Important for capture:** the default sink address is `127.0.0.1`. Loopback traffic
> never reaches the wire, so a Raspberry Pi capture node will see **nothing**. For real
> captures, run `sink.py` on the Pi (or another host) and set the sink host in the GUI to
> that machine's IP.

## A.4 The GUI, section by section

**1. Telemetry destination** — sink host, port, and protocol.

| Protocol | Behaviour | Why you'd pick it |
|---|---|---|
| `tcp` | New connection per beacon; new ephemeral source port each time | The default. One Zeek flow per beacon: cleanest labelling |
| `tcp-persistent` | One long-lived connection, length-framed sends | Mimics apps that hold a socket open. Many beacons collapse into one flow — tests whether your features survive that |
| `udp` | Fire-and-forget datagram | No handshake, no ACK. **Succeeds silently even with no sink running** |
| `http` | `POST /v1/telemetry` | Adds realistic headers and a response body |

**2. Beacon schedule** — the H₁ signal.

| Control | Range | What it changes |
|---|---|---|
| Schedule | periodic / poisson / batched | Timer-driven (low inter-arrival CV), memoryless (CV ≈ 1, looks like background), or accumulate N intervals then flush one big payload |
| Interval | 1–600 s | Mean time between beacons |
| Jitter | 0–100 % | Uniform spread around the interval; raises CV and defeats naive periodicity tests |
| Payload size | 64 B–64 KiB | `orig_bytes` per flow |
| Payload jitter | 0–90 % | Spread of payload size |
| Batch size | 1–60 | Intervals accumulated before a flush (batched mode only) |
| **Pre-send CPU burst** | 0–2000 ms | Real sha256+crc work before each send. **This is the cross-modal coupling knob** — set it to 0 to remove host/network dependence entirely |

**Send one now** fires an immediate beacon regardless of schedule, useful for aligning
clocks and for sanity-checking a capture.

**3. Background resource load** — how "idle" the idle app is.

| Control | Range | Notes |
|---|---|---|
| CPU per thread | 0–100 % | Duty-cycle target, not a guarantee — verify against Task Manager and calibrate |
| CPU threads | 0–8 | Work is sha256 on a 64 KiB buffer, which releases the GIL, so multiple threads do use multiple cores |
| Memory | 0–2048 MiB | Allocated and page-touched. **Do not exceed free RAM** |
| Disk write | 0–4096 KiB/s | Writes to `idlebeacon_logs/telemetry_cache/`, rotating at 8 MiB. Simulates local telemetry caching before a deferred upload |

**4. Profiles** — one click sets everything.

| Profile | Purpose |
|---|---|
| `silent` | Nothing at all: pure H₀ |
| `silent_control` (JSON) | Load on, **beacon off** — the control that proves your detector isn't just detecting CPU load |
| `low` | 2-minute beacons, 256 B, near-zero load |
| `mid` | 30 s, 1 KiB, light load — the everyday case |
| `high` | Poisson ~10 s, 8 KiB, 45 % × 2 threads — easy case / "does heavy load mask the beacon?" |
| `stealth` | Poisson 10-minute mean, 128 B, 2 ms pre-send — your detection floor |
| `batched` | 9 intervals accumulated, then one 4 KiB flush — the deferred-upload pattern |

**5. Annotation and status** — free-text `mark` events (write down what you did and when),
plus a **Minimise** button that moves the app into state S2.

**6. Log tail** — the last 200 ground-truth events, with the log file path underneath.

## A.5 Headless mode

```bash
python idlebeacon.py --headless --profile stealth --host 192.168.1.15 --port 5055 --duration 3600
python idlebeacon.py --headless --config profiles/mid.json --logdir ./run_07
```

| Flag | Meaning |
|---|---|
| `--headless` | No GUI. State is reported as `S3_HEADLESS` |
| `--profile NAME` | Built-in profile |
| `--config FILE` | JSON profile (overrides the built-in) |
| `--host`, `--port` | Override the sink address |
| `--duration N` | Seconds; `0` runs until Ctrl-C |
| `--logdir DIR` | Where the event log and telemetry cache go |

## A.6 Running a labelled session (the protocol)

1. Sync clocks on every machine (`chrony` on the Pi, `w32tm /resync` on Windows). Record
   the offset; you will need it for window alignment.
2. Start the sink on the Pi or a second host.
3. Start packet capture (`tcpdump -G 300 -w chunk_%Y%m%dT%H%M%SZ.pcap`) and ship chunks
   with the `perfPI` receiver.
4. Start `collect_counters.ps1` against the app's PID.
5. Start IDLEBEACON. Press **Send one now** — that beacon is your alignment marker, with a
   known timestamp on both sides.
6. Minimise, then leave the machine untouched for the session.
7. **Run the matched control**: the same duration, the same load, `silent_control.json`
   (beacon off). Without it you cannot tell a telemetry detector from a CPU-load detector.
8. Stop everything. Archive the PCAPs, `counters.csv`, `events_*.jsonl` and `sink_*.jsonl`
   together with a note of the clock offset.

## A.7 Joining the three data sources

The join key is **`local_port`**, logged on every beacon. It is the source port of the
flow, so a Zeek `conn.log` record maps back to this PID with no ambiguity.

```python
import json, pandas as pd

ev = pd.DataFrame([json.loads(l) for l in open("events_....jsonl")])
sends = ev[ev.event == "beacon_send"]

conn = pd.read_csv("conn.log", sep="\t", comment="#", header=None,
                   names=["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p",
                          "proto","service","duration","orig_bytes","resp_bytes",
                          "conn_state","local_orig","local_resp","missed_bytes",
                          "history","orig_pkts","orig_ip_bytes","resp_pkts",
                          "resp_ip_bytes","tunnel_parents"])

labelled = conn.merge(sends[["local_port","seq","ts","payload_bytes","app_state"]],
                      left_on="id.orig_p", right_on="local_port",
                      suffixes=("_flow","_app"))
# Every matched flow is a known H1 event. Everything else in the window is H0 background.
```

Counters join on time: bucket `counters.csv`'s `ts` and the event log's `ts` into the same
UTC windows (10 s / 30 s / 60 s / 5 min) and label a window H₁ if it contains a
`beacon_send`.

## A.8 Safety and hygiene

- Use an isolated lab network or a host you own. Windows Firewall will prompt on first
  listen — allow it only on the private profile.
- The memory slider allocates real RAM; the disk slider writes real bytes (capped at 8 MiB
  with rotation, but it does keep writing).
- `sink.py` accepts anything sent to its port. Don't leave it exposed on a routable
  interface longer than the experiment.
- The app is deliberately unstealthy: it is named honestly, logs everything, and will not
  hide, persist, or restart itself.

---

# PART B — ARCHITECTURE AND HOW IT WORKS

## B.1 Where it sits in the pipeline

```
   ┌──────────── Target host (Windows) ────────────┐
   │                                               │
   │   IDLEBEACON (GUI or headless)                │
   │     ├─ beacon thread ──► TCP/UDP/HTTP ────────┼──► wire ──► Pi (tcpdump)
   │     ├─ cpu / mem / disk threads               │              │  chunk_*.pcap
   │     ├─ state probe (S0..S3, 1 Hz)             │              │  perfPI transfer
   │     └─ event log  events_*.jsonl  ◄── labels  │              ▼
   │                                               │           WSL: Zeek → conn.log
   │   collect_counters.ps1 ──► counters.csv       │              │
   └───────────────────────────────────────────────┘              │
                    │                                             │
                    └──────────► join on UTC window + local_port ◄┘
                                          │
                                   labelled feature table
                                   (H0 / H1 per window)
```

## B.2 Thread model

| Thread | Period | Responsibility |
|---|---|---|
| `ib-telemetry` | 100 ms poll | Schedule, pre-send burst, payload build, send, log |
| `ib-cpu0..7` | 50 ms slices | Duty-cycled sha256/crc32 work; only `cpu_threads` of the pool are active |
| `ib-mem` | 500 ms | Grow/shrink 1 MiB blocks to the target; re-touch a random block to keep pages resident |
| `ib-disk` | 1 s | Append `disk_kbs` KiB to the telemetry cache, `fsync`, rotate at 8 MiB |
| `ib-housekeeping` | 1 s | Emit `state_change` when S0–S3 changes; diff the config and emit `config_change` |
| Tk main loop | 500 ms refresh | Widgets write straight into the shared `Config`; workers read it on their next cycle |

Configuration is a plain dataclass read by the workers, so a slider move takes effect
within one worker cycle and is recorded as a `config_change` event within one second. The
log is therefore a complete, ordered record of what the app was configured to do at every
moment of the session.

## B.3 Event-log schema

Every line is one JSON object. Common fields: `ts` (UTC epoch float), `ts_iso`, `mono`
(monotonic clock for drift-free ordering), `session`, `pid`, `event`.

| Event | Key fields | Use |
|---|---|---|
| `session_start` | host, os, python, full `config` | Session metadata |
| `state_change` | `app_state` (S0–S3), `user_idle_s` | Defines which windows are eligible for testing |
| `config_change` | `changed` dict | Audit of every knob move |
| `presend_start` / `presend_end` | `seq`, `planned_ms`, `actual_ms` | Ground truth for the host-side burst |
| `beacon_send` | `seq`, `local_ip`, **`local_port`**, `dst_ip`, `dst_port`, `payload_bytes`, `ack_bytes`, `duration_ms`, `app_state`, `label:"H1"` | The positive label + the flow join key |
| `beacon_error` | as above plus `error`, `label:"H1_attempted"` | The app tried to send and failed (blocked, sink down). Host-side evidence with no network evidence — exactly the case where counters carry the whole signal |
| `batch_accumulate` | `pending`, `batch_size` | Shows collection happening without transmission |
| `mark` | `text` | Operator annotation |
| `session_stop` | `stats` | Totals for reconciliation against the sink log |

## B.4 Beacon lifecycle

```
 t0            t0+presend_ms                     t1
 │                    │                          │
 ├── presend_start ───┤                          │
 │   sha256 + crc32 on 64 KiB, repeatedly        │
 │   → CPU time, instructions, cache refs,       │
 │     context switches rise on THIS pid         │
 │                    ├── beacon_send ───────────┤
 │                    │   connect / sendall / ack │
 │                    │   → flow appears on wire  │
```

That ordering is the whole point of the pre-send knob. It reproduces what a real app does
before phoning home (gather, serialise, compress, encrypt), and it creates the
**host-burst-then-network-event** pattern that a cross-modal detector can exploit and a
network-only or host-only detector cannot. Setting `presend_ms = 0` removes the coupling,
which gives you the ablation: *how much does cross-modal dependence actually buy?*

## B.5 What each knob is for, in research terms

| Knob | Network feature it moves | Host counter it moves | Question it answers |
|---|---|---|---|
| Interval | packet/flow rate, inter-arrival mean | wake-up frequency | How sparse can telemetry get before detection fails? |
| Jitter + poisson schedule | inter-arrival CV | — | Do periodicity tests survive an app that deliberately randomises? |
| Payload size | `orig_bytes`, bytes/packet | — | The volume floor of flow-based detection |
| Batch size | flows/window, bytes/flow | disk writes between flushes | Detecting *collection* when transmission is deferred |
| Pre-send burst | — | `% Processor Time`, cache/branch counters, context switches | Cross-modal coupling strength |
| CPU / memory / disk load | — | all process counters | Does host workload mask the beacon? (CryingJackpot's low/mid/high-profile question) |
| Protocol | flow count, ports, ACK asymmetry | — | Per-beacon flows vs one persistent flow |
| `silent_control` | nothing | full load | Confounder check: load without telemetry |

## B.6 Relationship to the project's reference material

Adapted from **CryingJackpot** (Gomes, Dias & Correia, 2020): the low/mid/high host-profile
idea for varying background workload, the hybrid-dataset construction approach, and the
process/memory/network counter families in its Table II.

Adapted from the **IRIS V2 lock-in document**: the H₀/H₁ framing, which is what the
`label` field encodes; the metric list in its §3.1–3.3, which the knobs are designed to
perturb one at a time; and the requirement for a known-idle baseline (§3.4), which
`silent_control.json` provides.

**Changed deliberately:** CryingJackpot's targets were loud, and its features used per-window
*averages*. Idle telemetry is a sub-second burst inside a quiet window, so per-window means
dilute it badly. Aggregate the counters with **max, sum, and count-above-baseline** as well
as the mean, and sweep shorter windows (10 s, 30 s) than that paper's 10–120 minutes.

## B.7 Known limitations (state these in the write-up)

1. **Not a real application.** No TLS, no real endpoints, no vendor SDK. Payload bytes are
   incompressible random padding, so any entropy-based feature will behave differently on
   real traffic.
2. **Counter resolution.** `Get-Counter` samples at ~1 s. A 25 ms pre-send burst is smeared
   across a 1 s bucket. Use ETW/PMC sampling if you need finer alignment, and treat 1 s as
   the coupling-window floor (Δ ≥ 1 s) in coincidence tests.
3. **CPU percentage is nominal.** It is a duty-cycle target under a Python interpreter; the
   achieved figure depends on the machine. Always report measured values.
4. **Windows performance counters are OS software counters**, not hardware PMU counters. If
   the paper claims HPCs, add Intel PCM/VTune or WPR PMC sampling.
5. **WSL2 cannot observe Windows processes.** `perf` inside WSL sees only the WSL VM. If the
   target is a Windows app, the host modality must come from Windows.
6. **Loopback is invisible to a capture node.** See the warning in A.3.
7. **UDP without a sink still "succeeds"** — no error is raised, so a `beacon_send` event
   can exist with no corresponding sink receipt. Reconcile against the sink log.
8. **The app is visible to itself.** Its own logging does a small amount of disk I/O every
   event, which appears in the process counters. It is constant and can be measured from a
   `silent` run, but it is not zero.
