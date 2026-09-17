#!/usr/bin/env python3
"""
IDLEBEACON sink - a minimal telemetry collector.

Accepts TCP (raw or length-framed), UDP and HTTP POST on the same port, replies
with a small ACK (so flows are outbound-dominant, as real telemetry is), and
writes a JSONL receipt log. Pair the receipt log with the app's event log to
confirm every beacon that left the host actually arrived.

  python sink.py --port 5055 --logdir ./sink_logs
  python sink.py --port 5055 --no-ack        # silent sink
"""

import argparse
import json
import socket
import socketserver
import threading
import time
from pathlib import Path

ACK = b"ACK\n"
HTTP_OK = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
           b"Content-Type: text/plain\r\nConnection: close\r\n\r\nok")

_lock = threading.Lock()
_fh = None
_ack = True


def record(**fields):
    rec = {"ts": time.time(),
           "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    rec.update(fields)
    line = json.dumps(rec, separators=(",", ":"))
    with _lock:
        _fh.write(line + "\n")
        _fh.flush()
    print(line, flush=True)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(30.0)
        peer_ip, peer_port = self.client_address[0], self.client_address[1]
        total = 0
        frames = 0
        t0 = time.time()
        is_http = False
        buf = b""
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                if total == 0 and data[:4] in (b"POST", b"GET ", b"HEAD"):
                    is_http = True
                total += len(data)
                frames += 1
                if is_http:
                    # Reply as soon as the full body is in: an HTTP client waits
                    # for the response, so we must not wait for EOF.
                    buf += data
                    head_end = buf.find(b"\r\n\r\n")
                    if head_end >= 0:
                        clen = 0
                        for line in buf[:head_end].split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                clen = int(line.split(b":", 1)[1].strip())
                        if len(buf) - (head_end + 4) >= clen:
                            try:
                                sock.sendall(HTTP_OK)
                            except OSError:
                                pass
                            break
                elif _ack:
                    try:
                        sock.sendall(ACK)
                    except OSError:
                        break
        except socket.timeout:
            pass
        finally:
            record(transport="http" if is_http else "tcp",
                   src_ip=peer_ip, src_port=peer_port,
                   bytes=total, recv_calls=frames,
                   duration_s=round(time.time() - t0, 3))


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def udp_loop(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        data, addr = s.recvfrom(65536)
        record(transport="udp", src_ip=addr[0], src_port=addr[1], bytes=len(data))
        if _ack:
            try:
                s.sendto(ACK, addr)
            except OSError:
                pass


def main():
    global _fh, _ack
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5055)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--logdir", default="./sink_logs")
    ap.add_argument("--no-ack", action="store_true")
    args = ap.parse_args()
    _ack = not args.no_ack

    logdir = Path(args.logdir)
    logdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    _fh = (logdir / f"sink_{stamp}.jsonl").open("a", encoding="utf-8")

    threading.Thread(target=udp_loop, args=(args.port,), daemon=True).start()
    srv = ThreadedTCPServer((args.bind, args.port), TCPHandler)
    print(f"sink listening on {args.bind}:{args.port} (tcp+udp+http), "
          f"ack={'on' if _ack else 'off'}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
        _fh.close()


if __name__ == "__main__":
    main()
