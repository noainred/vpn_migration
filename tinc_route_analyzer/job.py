"""Standalone analysis-job backend — runs the streaming flow analyzer as its
OWN process so the web portal stays responsive and is never the heavy processor.

The portal spawns this detached (``start_new_session``) to analyse server-side
capture CSVs (``.csv``/``.gz``, tens of GB) directly, or to consolidate several
servers' saved snapshots (``--merge``).  The engine is *exactly* the one the CLI
uses (:func:`flowcsv.analyze_flow_files`), so a job and ``tinc-flow-analyzer``
produce bit-identical, fact-based reports — single pass, memory bounded by
network cardinality, never the whole capture in RAM.

Progress and the final report are shared with the portal through two small
files written atomically to the output directory::

    <out>/job.json         status (state/packets/elapsed/heartbeat/pid/error)
    <out>/job_report.json  the aggregated report (same schema the CLI emits)

Because it runs in its own session, restarting/upgrading the portal does NOT
stop a job — the portal reconnects by reading ``job.json``.  Controlled by a
signal: SIGTERM/SIGINT = cancel (terminates parallel workers cleanly, writes a
final ``canceled`` status, exits).

Run (normally spawned by the portal)::

    python -m tinc_route_analyzer.job --out /path/portal_data -j 4 -- '/caps/*.csv.gz'
    python -m tinc_route_analyzer.job --out /path/portal_data --merge -- \
        /opt/portal_data_srv1 /opt/portal_data_srv2

Standard library only; targets Python 3.6+.
"""

import argparse
import glob as globmod
import json
import os
import re
import signal
import threading
import time

from .flowcsv import (FlowFilter, analyze_flow_files, filter_analysis,
                      load_report, merge_reports, to_dict)

STATUS_NAME = "job.json"
REPORT_NAME = "job_report.json"


class _Canceled(Exception):
    """Raised from the progress callback when a SIGTERM cancel is requested."""


def _atomic_write_json(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    os.replace(tmp, path)


def _is_capture_file(name):
    """True for raw capture files (*.csv / *.csv.gz / *.gz), but NOT aggregated
    snapshot JSON (flow_*.json[.gz]) — those belong to --merge, not raw analysis."""
    low = name.lower()
    if low.endswith(".csv") or low.endswith(".csv.gz"):
        return True
    if low.endswith(".gz") and not low.endswith(".json.gz") \
            and not any(t in name for t in ("flow_min_", "flow_hour_", "flow_day_")):
        return True
    return False


def _find_captures(root):
    """Recursively collect capture files under ``root`` (including subdirectories),
    skipping snapshot JSON. Sorted for deterministic parallel chunking."""
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if _is_capture_file(fn):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


# snapshot files: ``[<host>_]flow_(min|hour|day)_<key>.json[.gz]``
_SNAP_RE = re.compile(r"^(?:(?P<host>.+)_)?flow_(?:min|hour|day)_.+\.json(?:\.gz)?$")


def _merge_snapshots(root):
    """Recursively find each server's NEWEST snapshot under ``root``.

    Snapshots are grouped by (containing directory, host prefix) so that — for
    one server — only the most recent of its min/hour/day snapshots is taken
    (they are overlapping cumulative aggregates; loading more than one would
    double-count). This handles all consolidation layouts: one dir per server,
    several servers' host-prefixed files in one dir, and per-server subdirs.
    Returns a list of snapshot file paths (newest per server), sorted.
    """
    groups = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not _SNAP_RE.match(fn):
                continue
            host = _SNAP_RE.match(fn).group("host") or ""
            full = os.path.join(dirpath, fn)
            try:
                mt = os.path.getmtime(full)
            except OSError:
                continue
            key = (dirpath, host)
            cur = groups.get(key)
            if cur is None or mt > cur[0]:
                groups[key] = (mt, full)
    return sorted(v[1] for v in groups.values())


def _resolve(paths, merge=False):
    """Expand globs and directories into work items.

    * merge mode: a directory is searched **recursively** for snapshot files —
      the newest per server (grouped by directory + host prefix) — so a parent
      that holds several servers' subdirs, or one dir of host-prefixed files,
      all consolidate correctly without double-counting. Files/globs pass through
      as report files.
    * analyze mode: a directory is expanded — **recursively, including
      subdirectories** — to the capture files inside it (``*.csv`` / ``*.csv.gz``
      / ``*.gz``), so pointing at e.g. ``/data/tinc/`` reads logs from the whole
      tree. Aggregated snapshot JSON is skipped. Explicit ``**`` globs also work.

    Returns ``(resolved, missing)``.  Order is preserved; glob/dir matches are
    sorted so parallel chunking is deterministic.
    """
    resolved, missing = [], []
    for p in paths:
        p = (p or "").strip()
        if not p:
            continue
        if os.path.isdir(p):
            if merge:
                snaps = _merge_snapshots(p)     # newest per server, recursive
                if snaps:
                    resolved.extend(snaps)
                else:
                    resolved.append(p)          # fallback: load_report (live.json etc.)
            else:                                # analysis needs files -> recurse
                caps = _find_captures(p)
                if caps:
                    resolved.extend(caps)
                else:
                    missing.append(p + " (하위 디렉터리 포함 .csv/.gz 캡처 없음)")
            continue
        matched = sorted(globmod.glob(p, recursive=True))   # ** supported
        if matched:
            resolved.extend(matched)
        elif os.path.exists(p):
            resolved.append(p)
        else:
            missing.append(p)
    return resolved, missing


def _total_bytes(paths):
    """Sum of input file sizes (a fact for context; gz is the compressed size)."""
    total = 0
    for p in paths:
        try:
            if os.path.isfile(p):
                total += os.path.getsize(p)
        except OSError:
            pass
    return total


def run(paths, out_dir, workers=1, parse_times=True, merge=False,
        filter_spec=None, interval=1.5):
    """Analyse ``paths`` and write status + report into ``out_dir``.

    ``filter_spec`` is an optional exclusion dict (see :class:`FlowFilter`):
    ``{exclude_src, exclude_dst, exclude_proto, exclude_port, limit}``.
    Returns a process exit code (0 ok, 1 error, 130 canceled).
    """
    os.makedirs(out_dir, exist_ok=True)
    status_path = os.path.join(out_dir, STATUS_NAME)
    report_path = os.path.join(out_dir, REPORT_NAME)
    started = time.time()
    resolved, missing = _resolve(paths, merge=merge)
    flt = FlowFilter.from_spec(filter_spec)
    shared = {"packets": 0, "current": "", "done": False}
    cancel = {"v": False}
    base = {
        "mode": "merge" if merge else "analyze",
        "pid": os.getpid(), "started": started,
        "inputs": list(paths), "files_total": len(resolved),
        "missing": missing, "workers": workers, "parse_times": parse_times,
        "bytes_total": _total_bytes(resolved),
        "filter": flt.summary() if flt else None,
    }

    def write(state, **extra):
        now = time.time()
        payload = dict(base)
        payload.update({
            "state": state, "heartbeat": now,
            "elapsed": round(now - started, 1),
            "packets": shared["packets"], "current": shared["current"],
        })
        payload.update(extra)
        try:
            _atomic_write_json(status_path, payload)
        except OSError:
            pass

    def on_term(_signum, _frame):
        cancel["v"] = True
        # Safety net: if the worker is wedged in C and never reaches a cancel
        # check, hard-exit shortly so the portal's "중지" always takes effect.
        def _watchdog():
            time.sleep(4)
            shared["done"] = True
            try:
                write("canceled", error="사용자가 취소했습니다")
            except Exception:
                pass
            os._exit(130)
        threading.Thread(target=_watchdog, daemon=True).start()

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    write("running", pps=0.0)
    if not resolved:
        shared["done"] = True
        msg = "분석할 파일을 찾지 못했습니다"
        if missing:
            msg += ": " + ", ".join(missing)
        write("error", error=msg)
        return 1

    # Heartbeat writer: keeps job.json fresh (and computes pkt/s) independent of
    # how often the analysis progress callback fires.
    last = {"t": started, "p": 0}

    def heartbeat():
        while not shared["done"]:
            time.sleep(interval)
            if shared["done"]:
                break
            now = time.time()
            dt = now - last["t"]
            pps = (shared["packets"] - last["p"]) / dt if dt > 0 else 0.0
            last["t"], last["p"] = now, shared["packets"]
            write("running", pps=round(pps, 1))

    ht = threading.Thread(target=heartbeat, daemon=True)
    ht.start()

    state, extra, report = "done", {}, None
    try:
        if merge:
            reports = []
            for p in resolved:
                if cancel["v"]:
                    raise _Canceled()
                shared["current"] = os.path.basename(p.rstrip("/")) or p
                r = load_report(p)
                if r:
                    reports.append(r)
                    shared["packets"] = sum(
                        int((rep.get("meta") or {}).get("packets", 0) or 0)
                        for rep in reports)
            if not reports:
                raise RuntimeError(
                    "통합할 리포트를 찾지 못했습니다 (각 서버의 report.json 또는 "
                    "portal_data 디렉터리를 지정하세요)")
            analysis = merge_reports(reports)
            if flt is not None:
                analysis = filter_analysis(analysis, flt)
            shared["packets"] = analysis.packets
            stats = {"files": len(reports), "records": analysis.packets,
                     "sources": [{"name": os.path.basename(p.rstrip("/")) or p,
                                  "records": 0} for p in resolved]}
        else:
            def prog(n, path):
                if cancel["v"]:
                    raise _Canceled()
                shared["packets"] = n
                shared["current"] = os.path.basename(path)
            analysis, stats = analyze_flow_files(
                resolved, workers=max(1, workers), parse_times=parse_times,
                progress=prog, progress_every=200000, flow_filter=flt)
            shared["packets"] = analysis.packets
        report = to_dict(analysis, stats, limit=(flt.limit if flt else None))
        if flt is not None:
            report["meta"]["filter"] = flt.summary()
            report["meta"]["filter_basis"] = "aggregate" if merge else "packet"
    except _Canceled:
        state, extra = "canceled", {"error": "사용자가 취소했습니다"}
    except Exception as exc:  # pragma: no cover - defensive
        state, extra = "error", {"error": str(exc)}

    # Stop the heartbeat before the final write so it cannot clobber the
    # terminal status with a stale "running".
    shared["done"] = True
    ht.join(timeout=interval + 1.0)

    if state == "done" and report is not None:
        try:
            _atomic_write_json(report_path, report)
            meta = report.get("meta", {})
            extra = {"report": REPORT_NAME, "summary": {
                "packets": meta.get("packets", 0), "bytes": meta.get("bytes", 0),
                "hosts": meta.get("hosts", 0),
                "conversations": meta.get("conversations", 0),
                "services": meta.get("services", 0),
                "first_seen": meta.get("first_seen"),
                "last_seen": meta.get("last_seen"),
            }}
        except OSError as exc:
            state, extra = "error", {"error": "리포트 저장 실패: %s" % exc}

    write(state, **extra)
    return {"done": 0, "canceled": 130, "error": 1}.get(state, 0)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="tinc-flow-job",
        description="Detached streaming analysis/merge backend for the portal.")
    p.add_argument("--out", required=True, help="output dir for job.json/report")
    p.add_argument("-j", "--workers", type=int, default=1,
                   help="parallel workers (exact line-boundary chunking + merge)")
    p.add_argument("--no-time", action="store_true",
                   help="skip per-packet timestamp parsing for max throughput")
    p.add_argument("--merge", action="store_true",
                   help="consolidate several servers: inputs are report.json files "
                        "OR each server's portal_data directory (deduped)")
    p.add_argument("--filter", default=None, metavar="JSON",
                   help="exclusion spec as JSON: {exclude_src,exclude_dst,"
                        "exclude_proto,exclude_port,limit}")
    p.add_argument("paths", nargs="+", metavar="PATH",
                   help="capture CSV(s)/globs, or (with --merge) report files/dirs")
    args = p.parse_args(argv)
    spec = None
    if args.filter:
        try:
            spec = json.loads(args.filter)
        except ValueError:
            p.error("--filter must be valid JSON")
    return run(args.paths, args.out, workers=max(1, args.workers),
               parse_times=not args.no_time, merge=args.merge, filter_spec=spec)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
