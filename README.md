# PerfPI

**Detecting unexpected background network transmissions from a Windows process.**

![status](https://img.shields.io/badge/status-work--in--progress-orange)
![license](https://img.shields.io/badge/license-MIT-blue)
![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

> Research pipeline, not a product. It's rough in places. It works well enough for me.
> If you're solving a similar problem, some of it might be useful. If you want a polished
> tool, keep looking.

---

## Table of Contents

- [What this is](#what-this-is)
- [The problem](#the-problem)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Setup](#setup)
  - [Raspberry Pi](#raspberry-pi)
  - [Windows](#windows)
- [Attribution](#attribution)
- [Dataset generation](#dataset-generation)
- [Feature extraction](#feature-extraction)
- [Modeling](#modeling)
- [Repo layout](#repo-layout)
- [Reproducibility](#reproducibility)
- [Known issues](#known-issues)
- [Status](#status)
- [License](#license)

---

## What this is

ProcNet is a data-collection and modeling pipeline for one specific question:

**When a Windows application is idle, does it still send network traffic — and can we
tell that apart from normal background noise?**

It ties together packet captures from a Raspberry Pi, Windows Performance Counters,
hardware performance counters (`hpc.etl`), and Sysmon events to produce a labeled
feature matrix. From there, you train whatever model you want.

It is not a firewall. It is not a real-time monitor. It is not turnkey. It's a research
setup I built to generate a controlled dataset and evaluate detection methods on it.

---

## The problem

Capturing packets is easy. **Attributing them to a process is hard.**

If you capture on a Raspberry Pi, the PCAP tells you *what* went over the wire but not
*which process* on the Windows box sent it. To close that gap you need Windows-side
telemetry:

- **Sysmon Event ID 3** — logs network connections with PID, image path, and 5-tuple.
- **`pktmon`** — built into Windows 10/11, alternative to Sysmon.
- **WFP / ETW** — lower-level, more work, more complete.
- **`GetExtendedTcpTable`** — snapshot-based, misses short-lived connections.

Even with these, timestamps drift, UDP is often missed, and short-lived connections slip
through the cracks. Attribution is the hardest part of this project and where most of
the effort goes.

The second problem is **noise**. Idle Windows machines chatter constantly — telemetry,
updates, DNS, NTP, mDNS. Separating target-process traffic from OS noise is the whole
game.

---

## Architecture

```
┌─────────────────┐         ┌──────────────────────┐
│  Raspberry Pi   │         │   Windows Target     │
│                 │         │                      │
│  dumpcap        │         │  Sysmon  (Event 3)   │
│    ↓            │         │  logman  (PerfMon)   │
│  capture.pcap   │         │  wpr     (hpc.etl)   │
└────────┬────────┘         └──────────┬───────────┘
         │                             │
         │  SCP / shared drive         │
         └──────────────┬──────────────┘
                        ▼
              ┌──────────────────┐
              │  TShark  →  CSV  │
              │  wpaexporter     │
              │  PowerShell      │
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │ build_features.c │  ← alignment, windowing
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │  features.csv    │
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │  modeling/       │  ← sklearn, Keras
              └──────────────────┘
```

Two trial conditions:

| Label | Description |
|-------|-------------|
| **H0** | User-inactive, normal. Target app running, no injected traffic. |
| **H1** | User-inactive, with controlled background transmissions injected. |

Vary workload (CPU / memory / disk / idle) and transmission pattern (periodic / bursty /
random), keep everything else consistent.

---

## Requirements

### Hardware

- Raspberry Pi 4 (or any Pi with a stable NIC). Pi 3 works but drops more packets.
- Windows 10/11 box running the target application.
- A network path that lets the Pi see the Windows traffic. I use a managed switch with
  port mirroring. A network tap works too.

### Pi software

- Raspbian, but you can use whatever home lab/server setup you have
- `dumpcap` or `tcpdump`
- `chrony` — **do not skip this.** Clock drift kills attribution.

### Windows software

- [Wireshark / TShark](https://www.wireshark.org/download.html)
- [Windows Performance Toolkit](https://docs.microsoft.com/en-us/windows-hardware/test/wpt/) (WPR, WPAExporter, xperf)
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) (or use `pktmon`)
- NO Python 3.8+, as a matter of fact do not even have python on the same laptop its a disgrace
- OFC HAVE C TOOLS READY (MSYS2, GIT BASH, MINGW64, CMAKE, ETC). IF you dont have it ur a noob (jkjkjkjk)
- `logman` / `typeperf` (built in)

---

## Quick start

If you already have the tooling installed and just want to run a trial:

```bash
# On the Pi
./scripts/capture.sh start
# ... run the trial on Windows ...
./scripts/capture.sh stop
scp /mnt/captures/capture_*.pcap user@windows:/data/
```

```powershell
# On Windows
.\scripts\run_trial.ps1 -TrialId H0_2024_01_15_01 -Condition H0 -Workload cpu
```

```bash
# Back on Linux / WSL
./build/build_features --packets packets.csv --perf perf.csv --hpc hpc.csv \
                       --sysmon sysmon.csv --meta trial_meta.json \
                       --out features.csv --window 1.0 --overlap 0.5

python modeling/train.py --features features.csv --out results/
```

---

## Setup

### Raspberry Pi

```bash
sudo apt update
sudo apt install tcpdump chrony
sudo systemctl enable --now chrony
```

Verify clock sync before every trial:

```bash
chronyc tracking
```

`System time` offset should be under a few milliseconds. If it's not, fix it before
capturing.

Capture script (`scripts/capture.sh`):

```bash
#!/bin/bash
set -euo pipefail

INTERFACE="${INTERFACE:-eth0}"
OUTDIR="${OUTDIR:-/mnt/captures}"
mkdir -p "$OUTDIR"

case "${1:-}" in
  start)
    sudo tcpdump -i "$INTERFACE" \
      -w "$OUTDIR/capture_$(date +%Y%m%d_%H%M%S).pcap" \
      -b filesize:100000 -b files:10 \
      -q &
    echo $! | sudo tee /var/run/procnet.pid
    ;;
  stop)
    sudo kill "$(cat /var/run/procnet.pid)" || true
    sudo rm -f /var/run/procnet.pid
    ;;
  *)
    echo "usage: $0 {start|stop}" >&2
    exit 1
    ;;
esac


### Windows

#### Sysmon

Install with a config that logs Event ID 3. Minimal example (`config/sysmon.xml`):

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <NetworkConnect onmatch="exclude">
      <Image condition="is">C:\Windows\System32\svchost.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

```powershell
sysmon -accepteula -i config\sysmon.xml
```

Export events to CSV (`scripts/export_sysmon.ps1`):

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 3 } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time        = $x.Event.System.TimeCreated.SystemTime
      ProcessId   = $x.Event.EventData.Data[4].'#text'
      Image       = $x.Event.EventData.Data[5].'#text'
      SourceIp    = $x.Event.EventData.Data[14].'#text'
      SourcePort  = $x.Event.EventData.Data[15].'#text'
      DestIp      = $x.Event.EventData.Data[16].'#text'
      DestPort    = $x.Event.EventData.Data[17].'#text'
    }
  } | Export-Csv -Path C:\data\sysmon.csv -NoTypeInformation
```

#### Performance counters

```powershell
logman create counter ProcNetPerf -f csv -o C:\data\perf.csv `
  -c "\Processor(_Total)\% Processor Time" `
     "\Memory\Available MBytes" `
     "\PhysicalDisk(_Total)\Disk Bytes/sec" `
     "\Network Interface(*)\Bytes Total/sec" `
  -si 1
logman start ProcNetPerf
```

#### Hardware performance counters

```powershell
wpr -start CPU -start DiskIO -start Network -filemode
# run trial
wpr -stop C:\data\hpc.etl
wpaexporter -i C:\data\hpc.etl -o C:\data\hpc.csv
```

#### Packet CSV

```powershell
tshark -r C:\data\capture.pcap -T fields `
  -e frame.time_epoch -e ip.src -e ip.dst `
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport `
  -e frame.len -e _ws.col.Protocol -e tcp.flags `
  -e tcp.analysis.retransmission `
  -E header=y -E separator=, > C:\data\packets.csv
```

---

## Attribution

This is the part that will make or break your dataset. Read this before you do anything
else.

**PCAP alone cannot attribute traffic to a process.** You need Windows-side telemetry
and you need to correlate it carefully.

The matching strategy:

1. Extract 5-tuples and timestamps from both sides.
2. Join on `(src_ip, src_port, dst_ip, dst_port)`.
3. For each match, compute `abs(packet_time - sysmon_time)`.
4. Keep matches within a tolerance window (I use **±200 ms**).
5. If multiple Sysmon events match a single packet, pick the smallest delta.
6. If the smallest delta is above the tolerance, mark the packet as unattributed.

Attribution confidence for a window is the fraction of packets matched to the target
process. Low-confidence windows should be flagged, not silently dropped.


## Dataset generation

Two conditions:

- **H0** — user-inactive, normal. No injected traffic.
- **H1** — user-inactive, with controlled unexpected background transmissions.

Vary the workload (CPU-bound, memory-bound, disk-bound, idle) and the transmission
pattern (periodic, bursty, random). Keep OS version, app version, network config, power
plan, and environment constant.

Randomize trial order. Include washout periods between trials so the system settles.

Aim for **20–30 trials per condition per workload/pattern cell**. That's a lot of runs.
Automate as much as you can.

**Split train/val/test by trial, not by window.** Otherwise you leak information and
your metrics are garbage.

---

## Feature extraction

`build_features.c` reads the CSVs (packets, PerfMon, hpc, Sysmon), aligns them on a
common timeline, windows the data (default 1 s windows with 50% overlap), and outputs
one row per window with features and a label.

**Why C?** Speed and low-level control over timestamp handling. Python was too slow for
millions of packets. The code is not pretty, but it works.

### Inputs

- `packets.csv` from TShark
- `perf.csv` from PerfMon
- `hpc.csv` from `wpaexporter`
- `sysmon.csv` from Sysmon
- `trial_meta.json` with trial ID, condition, workload, pattern, start/end times

### Output

`features.csv`, one row per window. Columns:

| Group | Features |
|-------|----------|
| Network | packet count, byte count, rates, unique dst IPs/ports, protocol mix, TCP flags, retransmissions, RTT, DNS queries, TLS SNI, burstiness, inter-arrival stats |
| Workload | CPU, memory, disk I/O, context switches, interrupts |
| HPC | IPC, cache misses, branch misses, cycles, instructions |
| Attribution | fraction of packets matched to target process |
| Label | H0 / H1 |
| Metadata | trial ID, window start/end, workload, pattern |

### Build

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

### Run

```bash
./build_features --packets packets.csv --perf perf.csv --hpc hpc.csv \
                 --sysmon sysmon.csv --meta trial_meta.json \
                 --out features.csv --window 1.0 --overlap 0.5
```

---

## Modeling

Python scripts in `modeling/`. scikit-learn, pandas, numpy, matplotlib, Keras for the
autoencoder.

Workflow:

1. Load `features.csv`.
2. Split by trial ID into train/val/test.
3. Train baselines:
   - Threshold rules on packet rate, byte rate, unique destinations.
   - Isolation Forest, One-Class SVM, autoencoder.
   - Supervised: logistic regression, random forest, gradient boosting.
4. Evaluate: PR-AUC, ROC-AUC, precision/recall at fixed FPR (e.g. 1%), detection latency.
5. Run ablations: network only, HPC only, fused; window sizes; attribution confidence
   filtering.

Results go to `results/` with plots and a summary CSV.

---

## Repo layout

```
procnet/
├── config/               # Sysmon XML, PerfMon counter sets, trial templates
├── scripts/              # capture.sh, run_trial.ps1, export_sysmon.ps1
├── src/
│   └── build_features.c  # the C feature extractor
├── modeling/             # train.py, evaluate.py, notebooks
├── data/                 # raw and processed (gitignored, checksums kept)
├── results/              # model outputs, plots
├── CMakeLists.txt
├── requirements.txt
└── environment.yml
```

## Status

**Done**

- Pi capture script
- TShark conversion
- PerfMon logging
- WPR → `hpc.etl` → CSV
- Sysmon logging and export
- Basic attribution via 5-tuple + timestamp
- `build_features.c` skeleton with network and workload features
- Modeling notebook with baselines

**In progress**

- Finishing `build_features.c` (HPC features, better timestamp alignment)
- More H1 patterns (DNS tunneling, periodic beacons, large uploads)
- Improving attribution for UDP and encrypted traffic
- Hyperparameter tuning

**TODO**

- Add `pktmon` as an alternative to Sysmon
- Process-specific HPC attribution using ETW
- Automate the entire trial loop
- Tests for `build_features.c`
- Publish a small sample dataset

---

## License

MIT. See `LICENSE`.
