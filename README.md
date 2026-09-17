# ProcNet

Detecting unexpected background network transmissions from a Windows process.

## What this is

A research pipeline for one question: when a Windows application is idle, does it still send network traffic, and can we tell that apart from normal background noise?

It ties together packet captures from a Raspberry Pi, Windows Performance Counters, hardware performance counters (`hpc.etl`), and Sysmon events to produce a labeled feature matrix. Then you train whatever model you want.

Not a firewall. Not a real-time monitor. Not turnkey.

## The problem

Capturing packets is easy. Attributing them to a process is hard.

A PCAP from a Raspberry Pi tells you what went over the wire, not which process sent it. You need Windows-side telemetry:

- Sysmon Event ID 3 — network connections with PID, image path, 5-tuple
- `pktmon` — built into Windows 10/11, alternative to Sysmon
- WFP / ETW — lower-level, more complete, more work
- `GetExtendedTcpTable` — snapshot-based, misses short-lived connections

Timestamps drift, UDP is often missed, short-lived connections slip through. Attribution is the hardest part.

The second problem is noise. Idle Windows machines chatter constantly. Separating target-process traffic from OS noise is the whole game.

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
              │ build_features.c │
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │  features.csv    │
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │  modeling/       │
              └──────────────────┘
```

Two trial conditions:

| Label | Description |
|-------|-------------|
| H0 | User-inactive, normal. Target app running, no injected traffic. |
| H1 | User-inactive, with controlled background transmissions injected. |

Vary workload (CPU / memory / disk / idle) and transmission pattern (periodic / bursty / random). Keep everything else constant.

## Requirements

### Hardware

- Raspberry Pi 4 (Pi 3 works but drops more packets)
- Windows 10/11 box running the target application
- A network path that lets the Pi see the Windows traffic. Managed switch with port mirroring, or a network tap.

### Pi software

- Raspbian or any Linux
- `dumpcap` or `tcpdump`
- `chrony` — do not skip this. Clock drift kills attribution.

### Windows software

- Wireshark / TShark
- Windows Performance Toolkit (WPR, WPAExporter, xperf)
- Sysmon or `pktmon`
- Python 3.8+
- MSVC or MinGW + CMake
- `logman` / `typeperf`

## Quick start

```bash
# On the Pi
./scripts/capture.sh start
# run the trial on Windows
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

`System time` offset should be under a few milliseconds.

`scripts/capture.sh`:

```bash
#!/bin/bash
set -euo pipefail

INTERFACE="${INTERFACE:-eth0}"
OUTDIR="${OUTDIR:-/mnt/captures}"
mkdir -p "$OUTDIR"

case "${1:-}" in
  start)
    sudo dumpcap -i "$INTERFACE" \
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
```

### Windows

Sysmon config (`config/sysmon.xml`):

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

Export Sysmon events (`scripts/export_sysmon.ps1`):

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

PerfMon counters:

```powershell
logman create counter ProcNetPerf -f csv -o C:\data\perf.csv `
  -c "\Processor(_Total)\% Processor Time" `
     "\Memory\Available MBytes" `
     "\PhysicalDisk(_Total)\Disk Bytes/sec" `
     "\Network Interface(*)\Bytes Total/sec" `
  -si 1
logman start ProcNetPerf
```

Hardware counters:

```powershell
wpr -start CPU -start DiskIO -start Network -filemode
# run trial
wpr -stop C:\data\hpc.etl
wpaexporter -i C:\data\hpc.etl -o C:\data\hpc.csv
```

Packet CSV:

```powershell
tshark -r C:\data\capture.pcap -T fields `
  -e frame.time_epoch -e ip.src -e ip.dst `
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport `
  -e frame.len -e _ws.col.Protocol -e tcp.flags `
  -e tcp.analysis.retransmission `
  -E header=y -E separator=, > C:\data\packets.csv
```

## Attribution

PCAP alone cannot attribute traffic to a process. You need Windows-side telemetry and careful correlation.

Matching strategy:

1. Extract 5-tuples and timestamps from both sides.
2. Join on `(src_ip, src_port, dst_ip, dst_port)`.
3. Compute `abs(packet_time - sysmon_time)`.
4. Keep matches within ±200 ms.
5. If multiple Sysmon events match, pick the smallest delta.
6. If the smallest delta is above tolerance, mark the packet unattributed.

Attribution confidence for a window is the fraction of packets matched to the target process. Low-confidence windows should be flagged, not silently dropped.

Caveats:

- Sysmon does not log every connection. UDP is often missed.
- Short-lived TCP connections (DNS) may not appear.
- Pi and Windows clocks drift without NTP.
- Sequence numbers can help disambiguate when timestamps tie.

For `hpc.etl`, process attribution is harder. WPR's default CPU profile does not include PID in every event. Add `-start ProcessThread` or custom ETW providers, or correlate HPC data to the trial as a whole and accept it is not process-specific.

## Dataset generation

- H0: user-inactive, normal. No injected traffic.
- H1: user-inactive, with controlled unexpected background transmissions.

Vary workload (CPU, memory, disk, idle) and pattern (periodic, bursty, random). Keep OS version, app version, network config, power plan, and environment constant.

Randomize trial order. Include washout periods between trials.

Aim for 20–30 trials per condition per workload/pattern cell. Automate as much as you can.

Split train/val/test by trial, not by window. Otherwise you leak and your metrics are garbage.

## Feature extraction

`build_features.c` reads the CSVs (packets, PerfMon, hpc, Sysmon), aligns them on a common timeline, windows the data (default 1 s with 50% overlap), and outputs one row per window with features and a label.

Inputs:

- `packets.csv` from TShark
- `perf.csv` from PerfMon
- `hpc.csv` from `wpaexporter`
- `sysmon.csv` from Sysmon
- `trial_meta.json` with trial ID, condition, workload, pattern, start/end times

Output `features.csv`, one row per window:

| Group | Features |
|-------|----------|
| Network | packet count, byte count, rates, unique dst IPs/ports, protocol mix, TCP flags, retransmissions, RTT, DNS queries, TLS SNI, burstiness, inter-arrival stats |
| Workload | CPU, memory, disk I/O, context switches, interrupts |
| HPC | IPC, cache misses, branch misses, cycles, instructions |
| Attribution | fraction of packets matched to target process |
| Label | H0 / H1 |
| Metadata | trial ID, window start/end, workload, pattern |

Build:

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

Run:

```bash
./build_features --packets packets.csv --perf perf.csv --hpc hpc.csv \
                 --sysmon sysmon.csv --meta trial_meta.json \
                 --out features.csv --window 1.0 --overlap 0.5
```

## Modeling

Python scripts in `modeling/`. scikit-learn, pandas, numpy, matplotlib, Keras for the autoencoder.

1. Load `features.csv`.
2. Split by trial ID into train/val/test.
3. Train baselines:
   - Threshold rules on packet rate, byte rate, unique destinations
   - Isolation Forest, One-Class SVM, autoencoder
   - Supervised: logistic regression, random forest, gradient boosting
4. Evaluate: PR-AUC, ROC-AUC, precision/recall at fixed FPR (e.g. 1%), detection latency.
5. Ablations: network only, HPC only, fused; window sizes; attribution confidence filtering.

Results go to `results/`.

## Repo layout

```
procnet/
├── config/               # Sysmon XML, PerfMon counter sets, trial templates
├── scripts/              # capture.sh, run_trial.ps1, export_sysmon.ps1
├── src/
│   └── build_features.c
├── modeling/             # train.py, evaluate.py, notebooks
├── data/                 # raw and processed (gitignored, checksums kept)
├── results/
├── CMakeLists.txt
├── requirements.txt
└── environment.yml
```

## Reproducibility

- All configs in `config/`.
- Seeds fixed in modeling scripts.
- Tool and library versions recorded in `environment.yml` and `requirements.txt`.
- Hashes of raw data files stored in `data/checksums.txt`.
- Full trial loop scripted: `run_trial.ps1` on Windows, `capture.sh` on the Pi.

## Known issues

- Clock sync: if Pi and Windows clocks drift, attribution fails. Use NTP on both.
- Packet drops: `dumpcap` can drop under load. Monitor the drop counter.
- TShark performance: converting large PCAPs to CSV is slow. Use `-T fields`, only the fields you need.
- `hpc.etl` size: WPR files get huge. Limit duration, use `-filemode`.
- Attribution false positives: Sysmon Event ID 3 doesn't capture every packet.
- H1 injection realism: if you just run `curl` in a loop, the model learns that pattern and fails on real background transmissions.
- Data leakage: don't window across trial boundaries. Don't normalize before splitting.
- `build_features.c`: it's C. It will segfault. Use a debugger.

## Status

Done:

- Pi capture script
- TShark conversion
- PerfMon logging
- WPR → `hpc.etl` → CSV
- Sysmon logging and export
- Basic attribution via 5-tuple + timestamp
- `build_features.c` skeleton with network and workload features
- Modeling notebook with baselines

In progress:

- Finishing `build_features.c` (HPC features, better timestamp alignment)
- More H1 patterns (DNS tunneling, periodic beacons, large uploads)
- Improving attribution for UDP and encrypted traffic
- Hyperparameter tuning

TODO:

- Add `pktmon` as an alternative to Sysmon
- Process-specific HPC attribution using ETW
- Automate the entire trial loop
- Tests for `build_features.c`
- Publish a small sample dataset

## License

MIT.
