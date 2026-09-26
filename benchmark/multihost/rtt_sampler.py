#!/usr/bin/env python3
"""rtt_sampler.py OUT.json ID=IP:PORT ... : measure RTT from this host (the
coordinator host) to every signer DURING a benchmark configuration.

Phase 7B Level 2 allows no inbound ICMP on the signer hosts (only the signer port
from the coordinator), so RTT = TCP connect time to the signer port (SYN ->
SYN-ACK, one round trip), sampled every INTERVAL seconds until SIGTERM/SIGINT.
A refused or timed-out connect counts as a failure (e.g. a stopped signer); such
a signer gets rtt_ms null. Writes a JSON list the summarizer reads ("rtt_ms").
"""
import json
import signal
import socket
import statistics
import sys
import time

INTERVAL = 0.5
TIMEOUT = 2.0
out, targets = sys.argv[1], sys.argv[2:]
eps = []
for t in targets:
    sid, addr = t.split("=", 1)
    ip, port = addr.rsplit(":", 1)
    eps.append({"signer_id": int(sid), "ip": ip, "port": int(port), "ok": [], "fail": 0})

stop = False


def handler(*_):
    global stop
    stop = True


signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

while not stop:
    for e in eps:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        t0 = time.perf_counter()
        try:
            s.connect((e["ip"], e["port"]))
            e["ok"].append((time.perf_counter() - t0) * 1000)
        except OSError:
            e["fail"] += 1
        finally:
            s.close()
    time.sleep(INTERVAL)

rows = []
for e in eps:
    ok = e["ok"]
    rows.append({
        "signer_id": e["signer_id"], "ip": e["ip"], "port": e["port"],
        "rtt_ms": round(statistics.median(ok), 3) if ok else None,
        "rtt_min_ms": round(min(ok), 3) if ok else None,
        "rtt_max_ms": round(max(ok), 3) if ok else None,
        "samples": len(ok), "failures": e["fail"],
        "measured": "TCP connect to the signer port from the coordinator host, median during the run",
    })
with open(out, "w") as f:
    json.dump(rows, f, indent=1)
