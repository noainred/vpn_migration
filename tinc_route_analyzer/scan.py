"""Standalone capture backend — runs tshark + aggregation as its OWN process.

Decoupled from the web portal on purpose: the scan runs here, so killing or
upgrading the portal does NOT stop the scan. State is shared with the portal
through a small ``live.json`` written atomically to the output directory (plus a
heartbeat/pid so the portal can tell it is alive and reconnect after a restart).

Controlled by signals: SIGTERM/SIGINT = stop (final snapshot then exit),
SIGUSR1 = reset the in-memory aggregate (free memory, keep scanning).

Run (normally spawned detached by the portal)::

    python -m tinc_route_analyzer.scan --iface tun0 --out /path/portal_data \
        [--filter "not (host 10.0.0.5)"] [--interval 2]

Standard library only.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time

from .flowcsv import FlowAnalysis, iter_flow_records, to_dict

LIVE_NAME = "live.json"


def _tshark_argv(iface, capture_filter):
    argv = ["tshark", "-i", iface, "-l", "-n"]
    if capture_filter:
        argv += ["-f", capture_filter]
    argv += ["-T", "fields", "-E", "header=y", "-E", "separator=,",
             "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "udp.srcport", "-e", "udp.dstport",
             "-e", "tcp.flags", "-e", "ip.proto", "-e", "frame.len"]
    return argv


def write_live(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    os.replace(tmp, path)


def run(iface, capture_filter, out_dir, interval=2.0):
    os.makedirs(out_dir, exist_ok=True)
    live_path = os.path.join(out_dir, LIVE_NAME)
    lock = threading.Lock()
    state = {"a": FlowAnalysis(), "err": "", "running": True}
    stop = {"v": False}
    reset = {"v": False}
    started = time.time()

    proc = subprocess.Popen(
        _tshark_argv(iface, capture_filter), stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, universal_newlines=True, bufsize=1)

    def on_term(_signum, _frame):
        stop["v"] = True
        try:                      # unblock the blocking readline so we exit promptly
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass

    def on_reset(_signum, _frame):
        reset["v"] = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, on_reset)

    pps_state = {"t": started, "p": 0}

    def snapshot(running):
        with lock:
            data = to_dict(state["a"])
            pkts = state["a"].packets
            err = state["err"]
        now = time.time()
        dt = now - pps_state["t"]
        pps = (pkts - pps_state["p"]) / dt if dt > 0 else 0.0
        pps_state["t"], pps_state["p"] = now, pkts
        write_live(live_path, {
            "running": running, "iface": iface, "started": started,
            "heartbeat": now, "pid": os.getpid(), "packets": pkts,
            "pps": round(pps, 1), "error": err, "data": data,
        })

    def writer():
        while not stop["v"] and state["running"]:
            time.sleep(interval)
            try:
                snapshot(True)
            except Exception:
                pass

    wt = threading.Thread(target=writer, daemon=True)
    wt.start()
    snapshot(True)

    try:
        for rec in iter_flow_records(proc.stdout):
            if stop["v"]:
                break
            if reset["v"]:
                with lock:
                    state["a"] = FlowAnalysis()
                reset["v"] = False
                pps_state["p"] = 0
            with lock:
                state["a"].add_record(rec)
    except Exception as exc:  # pragma: no cover - depends on tshark
        with lock:
            state["err"] = str(exc)
    finally:
        state["running"] = False
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        snapshot(False)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="tinc-scan", description="Standalone tshark capture+aggregation backend.")
    p.add_argument("--iface", required=True)
    p.add_argument("--filter", default="", help="prebuilt BPF (validated by caller)")
    p.add_argument("--out", required=True, help="output dir for live.json")
    p.add_argument("--interval", type=float, default=2.0)
    args = p.parse_args(argv)
    return run(args.iface, args.filter, args.out, args.interval)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
