#!/usr/bin/env python3
"""
IDLEBEACON - a mock "inactive application that phones home".

Purpose: produce a controllable, fully labelled ground-truth signal for
cross-modal telemetry-detection research (network traffic + host counters).

The app does four things:
  1. Sits there looking idle (backgrounded / minimised / headless).
  2. Emits telemetry beacons on a configurable schedule to a configurable sink.
  3. Burns a configurable amount of CPU / memory / disk so the "idle" host
     workload can be varied independently of the beacon.
  4. Writes a JSONL ground-truth log of every single thing it did, with UTC
     timestamps, its PID, and the LOCAL SOURCE PORT of every beacon - which is
     what lets you attribute a Zeek flow back to this process with certainty.

Stdlib only. Python 3.8+. Runs on Windows (primary target) and Linux.

  GUI:       python idlebeacon.py
  Headless:  python idlebeacon.py --headless --config profiles/mid.json --duration 3600
"""

import argparse
import hashlib
import json
import os
import platform
import random
import socket
import sys
import threading
import time
import uuid
import zlib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

APP_NAME = "IDLEBEACON"
APP_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


@dataclass
class Config:
    """Everything the operator can vary. Mutated live; read by worker threads."""

    # --- telemetry destination ---
    dst_host: str = "127.0.0.1"
    dst_port: int = 5055
    protocol: str = "tcp"  # tcp | tcp-persistent | udp | http

    # --- beacon schedule ---
    beacon_enabled: bool = False
    schedule: str = "periodic"  # periodic | poisson | batched
    interval_s: float = 30.0
    jitter_pct: float = 10.0
    payload_bytes: int = 512
    payload_jitter_pct: float = 20.0
    batch_size: int = 6  # 'batched': collect N intervals, then flush once
    presend_ms: float = 0.0  # CPU burst before each send (serialise/compress)

    # --- background load ("how idle is idle") ---
    load_enabled: bool = False
    cpu_percent: float = 0.0  # per worker thread, 0-100
    cpu_threads: int = 1
    mem_mb: int = 0
    disk_kbs: int = 0  # KiB/s written to the local telemetry cache

    # --- housekeeping ---
    idle_grace_s: float = 60.0  # no input for this long => "idle"
    profile_name: str = "custom"

    def copy(self) -> "Config":
        return Config(**asdict(self))

    @staticmethod
    def from_dict(d: dict) -> "Config":
        known = {f.name for f in fields(Config)}
        return Config(**{k: v for k, v in d.items() if k in known})


PROTOCOLS = ("tcp", "tcp-persistent", "udp", "http")
SCHEDULES = ("periodic", "poisson", "batched")

# --------------------------------------------------------------------------
# Ground-truth event log
# --------------------------------------------------------------------------


class EventLog:
    """Append-only JSONL. One line per event. This is the label source."""

    def __init__(self, logdir: Path, session_id: str, mirror=None):
        logdir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.path = logdir / f"events_{stamp}_{session_id[:8]}.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self.session_id = session_id
        self.mirror = mirror  # callable(str) for the GUI log pane

    def emit(self, event: str, **fields_):
        rec = {
            "ts": time.time(),  # UTC epoch seconds, float
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time()%1*1e6):06d}Z",
            "mono": time.perf_counter(),  # drift-free ordering within session
            "session": self.session_id,
            "pid": os.getpid(),
            "event": event,
        }
        rec.update(fields_)
        line = json.dumps(rec, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
        if self.mirror:
            try:
                self.mirror(f"{rec['ts_iso'][11:23]}  {event}  " + " ".join(
                    f"{k}={v}" for k, v in fields_.items() if k != "payload"))
            except Exception:
                pass

    def close(self):
        with self._lock:
            try:
                self._fh.close()
            except Exception:
                pass


# --------------------------------------------------------------------------
# Windows / Linux activity-state probe
# --------------------------------------------------------------------------


class StateProbe:
    """Reports S0..S3 per the project's idle taxonomy.

    S0_ACTIVE           foreground + recent user input
    S1_FOREGROUND_IDLE  foreground, no input for >= idle_grace_s
    S2_BACKGROUND       running with a window, not foreground (or minimised)
    S3_HEADLESS         no GUI at all
    """

    def __init__(self, has_gui: bool):
        self.has_gui = has_gui
        self.available = False
        self._user32 = None
        if platform.system() == "Windows":
            try:
                import ctypes
                from ctypes import wintypes

                self._ctypes = ctypes
                self._wintypes = wintypes
                self._user32 = ctypes.windll.user32
                self._kernel32 = ctypes.windll.kernel32

                class LASTINPUTINFO(ctypes.Structure):
                    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

                self._LII = LASTINPUTINFO
                self.available = True
            except Exception:
                self.available = False

    def idle_seconds(self) -> float:
        if not self.available:
            return -1.0
        lii = self._LII()
        lii.cbSize = self._ctypes.sizeof(self._LII)
        if not self._user32.GetLastInputInfo(self._ctypes.byref(lii)):
            return -1.0
        return max(0.0, (self._kernel32.GetTickCount() - lii.dwTime) / 1000.0)

    def is_foreground(self) -> bool:
        if not self.available:
            return False
        hwnd = self._user32.GetForegroundWindow()
        if not hwnd:
            return False
        pid = self._wintypes.DWORD()
        self._user32.GetWindowThreadProcessId(hwnd, self._ctypes.byref(pid))
        return pid.value == os.getpid()

    def state(self, grace_s: float):
        if not self.has_gui:
            return "S3_HEADLESS", self.idle_seconds()
        if not self.available:
            return "S2_BACKGROUND_ASSUMED", -1.0
        idle = self.idle_seconds()
        if self.is_foreground():
            if idle >= 0 and idle < grace_s:
                return "S0_ACTIVE", idle
            return "S1_FOREGROUND_IDLE", idle
        return "S2_BACKGROUND", idle


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class Engine:
    """Owns config, worker threads, stats and the event log."""

    BURN_BUF = b"\xa5" * 65536  # sha256 on >2KB releases the GIL -> real multicore

    def __init__(self, cfg: Config, logdir: Path, has_gui: bool, mirror=None):
        self.cfg = cfg
        self.session_id = str(uuid.uuid4())
        self.log = EventLog(logdir, self.session_id, mirror=mirror)
        self.probe = StateProbe(has_gui)
        self.cache_dir = logdir / "telemetry_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._stop = threading.Event()
        self._threads = []
        self._mem_blocks = []
        self._persistent_sock = None
        self._seq = 0
        self._last_state = None
        self._last_cfg_snapshot = None
        self._force_send = threading.Event()

        self.stats = {
            "sends": 0,
            "bytes_sent": 0,
            "bytes_acked": 0,
            "errors": 0,
            "last_send_ts": 0.0,
            "next_send_ts": 0.0,
            "state": "-",
            "idle_s": -1.0,
        }
        self._stats_lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        self.log.emit(
            "session_start",
            app=APP_NAME,
            version=APP_VERSION,
            host=socket.gethostname(),
            os=f"{platform.system()} {platform.release()}",
            python=platform.python_version(),
            executable=sys.executable,
            clock_note="ts is UTC epoch; sync host+capture node with NTP/chrony",
            config=asdict(self.cfg),
        )
        self._last_cfg_snapshot = asdict(self.cfg)
        self._spawn(self._telemetry_loop, "telemetry")
        self._spawn(self._mem_loop, "mem")
        self._spawn(self._disk_loop, "disk")
        self._spawn(self._housekeeping_loop, "housekeeping")
        for i in range(8):  # pool; only cfg.cpu_threads of them do work
            self._spawn(self._cpu_loop, f"cpu{i}", args=(i,))

    def _spawn(self, fn, name, args=()):
        t = threading.Thread(target=fn, name=f"ib-{name}", args=args, daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self):
        self._stop.set()
        with self._stats_lock:
            snapshot = dict(self.stats)
        self.log.emit("session_stop", stats=snapshot)
        try:
            if self._persistent_sock:
                self._persistent_sock.close()
        except Exception:
            pass
        self.log.close()

    # -- annotations -------------------------------------------------------

    def mark(self, text: str):
        self.log.emit("mark", text=text)

    def send_now(self):
        self._force_send.set()

    def apply_profile(self, name: str, values: dict):
        for k, v in values.items():
            if hasattr(self.cfg, k):
                setattr(self.cfg, k, v)
        self.cfg.profile_name = name
        self.log.emit("profile_applied", profile=name, config=asdict(self.cfg))

    # -- telemetry ---------------------------------------------------------

    def _next_delay(self) -> float:
        c = self.cfg
        if c.schedule == "poisson":
            return random.expovariate(1.0 / max(c.interval_s, 0.001))
        j = c.interval_s * (c.jitter_pct / 100.0)
        return max(0.05, c.interval_s + random.uniform(-j, j))

    def _build_payload(self, n_events: int) -> bytes:
        """A telemetry-shaped JSON batch, padded/compressed to the target size."""
        c = self.cfg
        target = max(64, int(c.payload_bytes * (1 + random.uniform(
            -c.payload_jitter_pct / 100.0, c.payload_jitter_pct / 100.0))))
        doc = {
            "schema": "idlebeacon/telemetry/1",
            "session": self.session_id,
            "seq": self._seq,
            "ts": time.time(),
            "app_version": APP_VERSION,
            "events": [
                {"n": f"evt_{i}", "t": time.time() - i, "v": random.randint(0, 9999)}
                for i in range(max(1, n_events))
            ],
        }
        body = json.dumps(doc).encode()
        if len(body) < target:
            body += b"\x00" + os.urandom(target - len(body) - 1)
        return body[:target] if len(body) > target else body

    def _burn(self, seconds: float):
        """Real work (sha256 + zlib), so it shows in HPCs and process counters."""
        if seconds <= 0:
            return
        end = time.perf_counter() + seconds
        while time.perf_counter() < end and not self._stop.is_set():
            h = hashlib.sha256()
            h.update(self.BURN_BUF)
            zlib.crc32(self.BURN_BUF)
            h.digest()

    def _telemetry_loop(self):
        pending = 0
        next_at = time.time() + 1.0
        while not self._stop.is_set():
            forced = self._force_send.wait(timeout=0.1)
            if forced:
                self._force_send.clear()
            elif not self.cfg.beacon_enabled:
                next_at = time.time() + self._next_delay()
                with self._stats_lock:
                    self.stats["next_send_ts"] = 0.0
                continue
            else:
                with self._stats_lock:
                    self.stats["next_send_ts"] = next_at
                if time.time() < next_at:
                    continue

            if not forced:
                next_at = time.time() + self._next_delay()

            if self.cfg.schedule == "batched" and not forced:
                pending += 1
                self.log.emit("batch_accumulate", pending=pending,
                              batch_size=self.cfg.batch_size)
                if pending < max(1, self.cfg.batch_size):
                    continue
                n_events = pending
                pending = 0
            else:
                n_events = 1

            self._seq += 1
            seq = self._seq

            # ---- pre-send CPU burst: the cross-modal coupling signal ----
            pre_ms = float(self.cfg.presend_ms)
            if pre_ms > 0:
                self.log.emit("presend_start", seq=seq, planned_ms=pre_ms)
                t0 = time.perf_counter()
                self._burn(pre_ms / 1000.0)
                self.log.emit("presend_end", seq=seq,
                              actual_ms=round((time.perf_counter() - t0) * 1000, 3))

            payload = self._build_payload(n_events)
            self._send(payload, seq, n_events, forced)

    def _send(self, payload: bytes, seq: int, n_events: int, forced: bool):
        c = self.cfg
        state, idle = self.probe.state(c.idle_grace_s)
        t_start = time.time()
        p0 = time.perf_counter()
        local = None
        acked = 0
        err = None
        try:
            if c.protocol == "udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("", 0))
                local = s.getsockname()
                s.sendto(payload, (c.dst_host, c.dst_port))
                s.close()
            elif c.protocol == "http":
                import http.client

                conn = http.client.HTTPConnection(c.dst_host, c.dst_port, timeout=5)
                conn.request("POST", "/v1/telemetry", body=payload,
                             headers={"Content-Type": "application/json",
                                      "User-Agent": f"{APP_NAME}/{APP_VERSION}"})
                local = conn.sock.getsockname() if conn.sock else None
                resp = conn.getresponse()
                acked = len(resp.read())
                conn.close()
            elif c.protocol == "tcp-persistent":
                if self._persistent_sock is None:
                    s = socket.create_connection((c.dst_host, c.dst_port), timeout=5)
                    s.settimeout(2.0)
                    self._persistent_sock = s
                    self.log.emit("connection_open", protocol=c.protocol,
                                  local_ip=s.getsockname()[0], local_port=s.getsockname()[1],
                                  dst_ip=c.dst_host, dst_port=c.dst_port)
                s = self._persistent_sock
                local = s.getsockname()
                s.sendall(len(payload).to_bytes(4, "big") + payload)
                try:
                    acked = len(s.recv(64))
                except socket.timeout:
                    acked = 0
            else:  # plain tcp: new connection (and new ephemeral port) per beacon
                s = socket.create_connection((c.dst_host, c.dst_port), timeout=5)
                s.settimeout(2.0)
                local = s.getsockname()
                s.sendall(payload)
                try:
                    s.shutdown(socket.SHUT_WR)
                    acked = len(s.recv(64))
                except (socket.timeout, OSError):
                    acked = 0
                s.close()
        except Exception as e:  # sink down, network blocked, etc.
            err = f"{type(e).__name__}: {e}"
            if c.protocol == "tcp-persistent":
                try:
                    self._persistent_sock.close()
                except Exception:
                    pass
                self._persistent_sock = None

        dur_ms = round((time.perf_counter() - p0) * 1000, 3)
        with self._stats_lock:
            if err:
                self.stats["errors"] += 1
            else:
                self.stats["sends"] += 1
                self.stats["bytes_sent"] += len(payload)
                self.stats["bytes_acked"] += acked
                self.stats["last_send_ts"] = t_start

        self.log.emit(
            "beacon_send" if not err else "beacon_error",
            seq=seq,
            forced=forced,
            protocol=c.protocol,
            schedule=c.schedule,
            n_events=n_events,
            payload_bytes=len(payload),
            ack_bytes=acked,
            duration_ms=dur_ms,
            local_ip=local[0] if local else None,
            local_port=local[1] if local else None,   # <-- flow -> PID join key
            dst_ip=c.dst_host,
            dst_port=c.dst_port,
            app_state=state,
            user_idle_s=round(idle, 1),
            error=err,
            label="H1" if not err else "H1_attempted",
        )

    # -- resource load -----------------------------------------------------

    def _cpu_loop(self, idx: int):
        slice_s = 0.05
        while not self._stop.is_set():
            c = self.cfg
            active = c.load_enabled and idx < max(0, int(c.cpu_threads)) and c.cpu_percent > 0
            if not active:
                time.sleep(0.2)
                continue
            duty = min(100.0, float(c.cpu_percent)) / 100.0
            self._burn(slice_s * duty)
            rest = slice_s * (1.0 - duty)
            if rest > 0:
                time.sleep(rest)

    def _mem_loop(self):
        MB = 1024 * 1024
        while not self._stop.is_set():
            target = max(0, int(self.cfg.mem_mb)) if self.cfg.load_enabled else 0
            while len(self._mem_blocks) < target:
                b = bytearray(MB)
                b[::4096] = b"\x01" * len(b[::4096])  # touch every page -> commit
                self._mem_blocks.append(b)
            while len(self._mem_blocks) > target:
                self._mem_blocks.pop()
            if self._mem_blocks:  # keep pages resident in the working set
                blk = random.choice(self._mem_blocks)
                blk[0] = (blk[0] + 1) % 256
            time.sleep(0.5)

    def _disk_loop(self):
        path = self.cache_dir / "telemetry_cache.bin"
        rotate_at = 8 * 1024 * 1024
        while not self._stop.is_set():
            kbs = max(0, int(self.cfg.disk_kbs)) if self.cfg.load_enabled else 0
            if kbs <= 0:
                time.sleep(0.5)
                continue
            try:
                with path.open("ab") as fh:
                    fh.write(os.urandom(kbs * 1024))
                    fh.flush()
                    os.fsync(fh.fileno())
                if path.stat().st_size > rotate_at:
                    path.unlink(missing_ok=True)
            except Exception as e:
                self.log.emit("disk_error", error=str(e))
                time.sleep(2)
            time.sleep(1.0)

    # -- housekeeping: state changes + config-change auditing --------------

    def _housekeeping_loop(self):
        while not self._stop.is_set():
            state, idle = self.probe.state(self.cfg.idle_grace_s)
            with self._stats_lock:
                self.stats["state"] = state
                self.stats["idle_s"] = idle
            if state != self._last_state:
                self.log.emit("state_change", app_state=state,
                              previous=self._last_state, user_idle_s=round(idle, 1))
                self._last_state = state

            snap = asdict(self.cfg)
            if snap != self._last_cfg_snapshot:
                delta = {k: v for k, v in snap.items()
                         if self._last_cfg_snapshot.get(k) != v}
                self.log.emit("config_change", changed=delta)
                self._last_cfg_snapshot = snap
            time.sleep(1.0)


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------

BUILTIN_PROFILES = {
    "silent": dict(beacon_enabled=False, load_enabled=False, cpu_percent=0,
                   mem_mb=0, disk_kbs=0, profile_name="silent"),
    "low": dict(beacon_enabled=True, schedule="periodic", interval_s=120,
                jitter_pct=5, payload_bytes=256, presend_ms=5,
                load_enabled=True, cpu_percent=1, cpu_threads=1, mem_mb=32,
                disk_kbs=0, profile_name="low"),
    "mid": dict(beacon_enabled=True, schedule="periodic", interval_s=30,
                jitter_pct=15, payload_bytes=1024, presend_ms=25,
                load_enabled=True, cpu_percent=8, cpu_threads=1, mem_mb=128,
                disk_kbs=16, profile_name="mid"),
    "high": dict(beacon_enabled=True, schedule="poisson", interval_s=10,
                 jitter_pct=30, payload_bytes=8192, presend_ms=120,
                 load_enabled=True, cpu_percent=45, cpu_threads=2, mem_mb=512,
                 disk_kbs=128, profile_name="high"),
    "stealth": dict(beacon_enabled=True, schedule="poisson", interval_s=600,
                    jitter_pct=50, payload_bytes=128, presend_ms=2,
                    load_enabled=True, cpu_percent=1, cpu_threads=1, mem_mb=64,
                    disk_kbs=0, profile_name="stealth"),
    "batched": dict(beacon_enabled=True, schedule="batched", interval_s=20,
                    batch_size=9, payload_bytes=4096, presend_ms=60,
                    load_enabled=True, cpu_percent=3, cpu_threads=1, mem_mb=96,
                    disk_kbs=8, profile_name="batched"),
}


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------


def run_gui(cfg: Config, logdir: Path):
    import tkinter as tk
    from tkinter import filedialog, ttk

    log_lines = []

    def mirror(line):
        log_lines.append(line)
        del log_lines[:-400]

    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}  -  mock idle-telemetry app  (PID {os.getpid()})")
    root.geometry("760x820")

    engine = Engine(cfg, logdir, has_gui=True, mirror=mirror)

    # --- tk variables bound to config -------------------------------------
    V = {}

    def bind(name, kind=tk.DoubleVar):
        v = kind(value=getattr(cfg, name))
        V[name] = v

        def _on(*_):
            try:
                val = v.get()
            except Exception:
                return
            cur = getattr(cfg, name)
            setattr(cfg, name, type(cur)(val) if not isinstance(cur, bool) else bool(val))
        v.trace_add("write", _on)
        return v

    # All slider-backed values are DoubleVars (a ttk.Scale writes floats; an
    # IntVar would raise TclError). The Config dataclass casts back to int.
    for n in ("interval_s", "jitter_pct", "payload_bytes", "presend_ms",
              "cpu_percent", "mem_mb", "disk_kbs", "batch_size",
              "payload_jitter_pct", "idle_grace_s", "cpu_threads"):
        bind(n)
    for n in ("beacon_enabled", "load_enabled"):
        bind(n, tk.BooleanVar)
    for n in ("dst_host", "protocol", "schedule"):
        bind(n, tk.StringVar)
    bind("dst_port", tk.IntVar)

    nb_pad = dict(padx=8, pady=4)  # pack() options; 'sticky' is grid-only

    def slider(parent, label, var, lo, hi, row, resolution=1, unit=""):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=8, pady=3)
        s = ttk.Scale(parent, from_=lo, to=hi, variable=var, orient="horizontal")
        s.grid(row=row, column=1, sticky="we", padx=6)
        ent = ttk.Entry(parent, textvariable=var, width=9, justify="right")
        ent.grid(row=row, column=2, padx=(0, 4))
        ttk.Label(parent, text=unit, width=7).grid(row=row, column=3, sticky="w")
        parent.columnconfigure(1, weight=1)

    # --- destination ------------------------------------------------------
    f_dst = ttk.LabelFrame(root, text="1. Telemetry destination")
    f_dst.pack(fill="x", **nb_pad)
    ttk.Label(f_dst, text="Sink host").grid(row=0, column=0, padx=8, pady=5, sticky="w")
    ttk.Entry(f_dst, textvariable=V["dst_host"], width=18).grid(row=0, column=1, sticky="w")
    ttk.Label(f_dst, text="Port").grid(row=0, column=2, padx=(12, 4))
    ttk.Entry(f_dst, textvariable=V["dst_port"], width=7).grid(row=0, column=3, sticky="w")
    ttk.Label(f_dst, text="Protocol").grid(row=0, column=4, padx=(12, 4))
    ttk.Combobox(f_dst, textvariable=V["protocol"], values=list(PROTOCOLS),
                 width=14, state="readonly").grid(row=0, column=5, padx=(0, 8))

    # --- beacon -----------------------------------------------------------
    f_b = ttk.LabelFrame(root, text="2. Beacon schedule  (the H1 signal)")
    f_b.pack(fill="x", **nb_pad)
    top = ttk.Frame(f_b)
    top.grid(row=0, column=0, columnspan=4, sticky="we", pady=(4, 0))
    ttk.Checkbutton(top, text="Beacon ON", variable=V["beacon_enabled"]).pack(side="left", padx=8)
    ttk.Label(top, text="Schedule").pack(side="left", padx=(12, 4))
    ttk.Combobox(top, textvariable=V["schedule"], values=list(SCHEDULES),
                 width=12, state="readonly").pack(side="left")
    ttk.Button(top, text="Send one now", command=engine.send_now).pack(side="left", padx=12)
    slider(f_b, "Interval", V["interval_s"], 1, 600, 1, unit="s")
    slider(f_b, "Jitter", V["jitter_pct"], 0, 100, 2, unit="%")
    slider(f_b, "Payload size", V["payload_bytes"], 64, 65536, 3, unit="bytes")
    slider(f_b, "Payload jitter", V["payload_jitter_pct"], 0, 90, 4, unit="%")
    slider(f_b, "Batch size", V["batch_size"], 1, 60, 5, unit="intervals")
    slider(f_b, "Pre-send CPU burst", V["presend_ms"], 0, 2000, 6, unit="ms")

    # --- load -------------------------------------------------------------
    f_l = ttk.LabelFrame(root, text="3. Background resource load  (how 'idle' the idle app is)")
    f_l.pack(fill="x", **nb_pad)
    ttk.Checkbutton(f_l, text="Load ON", variable=V["load_enabled"]).grid(
        row=0, column=0, sticky="w", padx=8, pady=4)
    slider(f_l, "CPU per thread", V["cpu_percent"], 0, 100, 1, unit="%")
    slider(f_l, "CPU threads", V["cpu_threads"], 0, 8, 2, unit="threads")
    slider(f_l, "Memory", V["mem_mb"], 0, 2048, 3, unit="MiB")
    slider(f_l, "Disk write", V["disk_kbs"], 0, 4096, 4, unit="KiB/s")

    # --- profiles ---------------------------------------------------------
    f_p = ttk.LabelFrame(root, text="4. Profiles")
    f_p.pack(fill="x", **nb_pad)

    def apply_profile(name):
        engine.apply_profile(name, BUILTIN_PROFILES[name])
        for k, v in V.items():
            try:
                v.set(getattr(cfg, k))
            except Exception:
                pass

    for i, name in enumerate(BUILTIN_PROFILES):
        ttk.Button(f_p, text=name, width=10,
                   command=lambda n=name: apply_profile(n)).grid(row=0, column=i, padx=4, pady=6)

    def save_cfg():
        p = filedialog.asksaveasfilename(defaultextension=".json",
                                         initialfile="profile.json")
        if p:
            Path(p).write_text(json.dumps(asdict(cfg), indent=2))
            engine.log.emit("config_saved", path=p)

    def load_cfg():
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if p:
            d = json.loads(Path(p).read_text())
            engine.apply_profile(Path(p).stem, d)
            for k, v in V.items():
                try:
                    v.set(getattr(cfg, k))
                except Exception:
                    pass

    ttk.Button(f_p, text="Save...", command=save_cfg).grid(row=0, column=8, padx=(20, 4))
    ttk.Button(f_p, text="Load...", command=load_cfg).grid(row=0, column=9, padx=4)

    # --- annotation + status ---------------------------------------------
    f_m = ttk.LabelFrame(root, text="5. Annotation and status")
    f_m.pack(fill="x", **nb_pad)
    mark_var = tk.StringVar(value="")
    ttk.Entry(f_m, textvariable=mark_var, width=44).grid(row=0, column=0, padx=8, pady=5)

    def do_mark():
        engine.mark(mark_var.get() or "(empty)")
        mark_var.set("")

    ttk.Button(f_m, text="Mark event", command=do_mark).grid(row=0, column=1)
    ttk.Button(f_m, text="Minimise (go S2)", command=root.iconify).grid(row=0, column=2, padx=8)

    status = tk.StringVar(value="starting...")
    ttk.Label(f_m, textvariable=status, font=("TkFixedFont", 9)).grid(
        row=1, column=0, columnspan=4, sticky="w", padx=8, pady=(0, 6))

    # --- live log ---------------------------------------------------------
    f_log = ttk.LabelFrame(root, text="6. Ground-truth event log (tail)")
    f_log.pack(fill="both", expand=True, **nb_pad)
    txt = tk.Text(f_log, height=12, wrap="none", font=("TkFixedFont", 8))
    txt.pack(fill="both", expand=True, padx=6, pady=6)
    ttk.Label(f_log, text=str(engine.log.path), font=("TkFixedFont", 8)).pack(
        anchor="w", padx=6, pady=(0, 4))

    def refresh():
        with engine._stats_lock:
            st = dict(engine.stats)
        nxt = st["next_send_ts"]
        nxt_s = f"{max(0, nxt - time.time()):5.1f}s" if nxt else "  --  "
        status.set(
            f"PID {os.getpid()}  state={st['state']}  user_idle={st['idle_s']:.0f}s | "
            f"sends={st['sends']}  bytes={st['bytes_sent']}  ack={st['bytes_acked']}  "
            f"err={st['errors']}  next in {nxt_s}")
        txt.delete("1.0", "end")
        txt.insert("1.0", "\n".join(log_lines[-200:]))
        txt.see("end")
        root.after(500, refresh)

    def on_close():
        engine.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    engine.start()
    refresh()
    root.mainloop()


# --------------------------------------------------------------------------
# Headless
# --------------------------------------------------------------------------


def run_headless(cfg: Config, logdir: Path, duration: float):
    engine = Engine(cfg, logdir, has_gui=False, mirror=lambda s: print(s, flush=True))
    engine.start()
    print(f"{APP_NAME} headless. PID={os.getpid()} log={engine.log.path}")
    t_end = time.time() + duration if duration > 0 else float("inf")
    try:
        while time.time() < t_end:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        print("stopped.")


def main():
    ap = argparse.ArgumentParser(description=f"{APP_NAME} - mock idle telemetry app")
    ap.add_argument("--headless", action="store_true", help="no GUI (state S3)")
    ap.add_argument("--config", help="JSON profile to start from")
    ap.add_argument("--profile", choices=list(BUILTIN_PROFILES), help="built-in profile")
    ap.add_argument("--logdir", default="./idlebeacon_logs")
    ap.add_argument("--duration", type=float, default=0, help="seconds (0 = forever)")
    ap.add_argument("--host"), ap.add_argument("--port", type=int)
    args = ap.parse_args()

    cfg = Config()
    if args.profile:
        for k, v in BUILTIN_PROFILES[args.profile].items():
            setattr(cfg, k, v)
    if args.config:
        cfg = Config.from_dict({**asdict(cfg), **json.loads(Path(args.config).read_text())})
    if args.host:
        cfg.dst_host = args.host
    if args.port:
        cfg.dst_port = args.port

    logdir = Path(args.logdir)
    if args.headless:
        run_headless(cfg, logdir, args.duration)
    else:
        run_gui(cfg, logdir)


if __name__ == "__main__":
    main()
