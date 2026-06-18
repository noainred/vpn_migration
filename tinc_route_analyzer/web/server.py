"""A dependency-free web portal for the tinc route analyzer.

The browser reads the log files locally and POSTs their text content as JSON,
so the server never has to parse multipart uploads — it just runs the existing
analyzer and returns structured results.  Everything (HTML/CSS/JS) is served
from disk with no external CDN, so the portal works fully offline / air-gapped.

Run with::

    python3 -m tinc_route_analyzer.web --port 8080
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Optional
from urllib.parse import parse_qs, urlparse


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """http.server.ThreadingHTTPServer is 3.7+; define it for Python 3.6."""

    daemon_threads = True

from . import persistence, updater
from .. import flowcsv, reporter, version_info
from ..analyzer import analyze_texts
from ..flowcsv import FlowAnalysis, iter_flow_records, to_dict
from ..parser import DEFAULT_YEAR

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
# samples/ lives at the repository root, two levels above this package.
SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "samples",
)
MAX_BODY = 256 * 1024 * 1024  # 256 MiB upload guard
# Browser uploads stream the whole file into memory, so cap direct CSV analysis;
# above this, users run the streaming CLI and upload the small report.json.
MAX_INLINE_CSV = 64 * 1024 * 1024

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


def _flow_exports(data) -> dict:
    return {
        "conversations_csv": flowcsv.render_conversations_csv(data),
        "policies_csv": flowcsv.render_policies_csv(data),
        "hosts_csv": flowcsv.render_hosts_csv(data),
        "dot": flowcsv.render_dot(data),
    }


def _try_flow_report(content: str):
    """Return a parsed flow report dict if ``content`` is one, else ``None``.

    This is the path for very large captures: the user processes them with the
    streaming CLI (``tinc-flow-analyzer -f json``) and uploads the small
    ``report.json`` here for visualisation.
    """
    if not content or content.lstrip()[:1] != "{":
        return None
    try:
        obj = json.loads(content)
    except ValueError:
        return None
    if isinstance(obj, dict) and obj.get("mode") == "flow" \
            and "conversations" in obj and "hosts" in obj:
        return obj
    return None


def analyze_payload(payload: dict) -> dict:
    """Pure analysis entry point used by the HTTP handler (and tests).

    Accepts three kinds of input and auto-detects which: a pre-aggregated flow
    report (report.json from the CLI), a tshark/Wireshark packet CSV, or tinc
    log files.
    """
    files = payload.get("files") or []
    if not files:
        return {"ok": False, "error": "no files provided"}

    items = [
        (f.get("name") or "upload", (f.get("node") or "").strip() or None,
         f.get("content") or "")
        for f in files
    ]

    # 1) pre-aggregated flow report.json file(s). Several at once are merged
    #    (deduplicating communication pairs) — multi-server consolidation.
    reports = []
    for _name, _node, content in items:
        report = _try_flow_report(content)
        if report is not None:
            reports.append(report)
    if reports:
        if len(reports) == 1:
            data = reports[0]
            merged_note = False
        else:
            data = flowcsv.to_dict(flowcsv.merge_reports(reports))
            merged_note = True
        return {"ok": True, "mode": "flow", "fromReport": True,
                "merged": merged_note, "mergedCount": len(reports),
                "data": data,
                "summaryText": flowcsv.render_summary(data),
                "exports": _flow_exports(data)}

    # 2) tshark/Wireshark packet CSV -> flow analysis (guarded for size).
    if any(flowcsv.looks_like_flow_csv(c) for _n, _no, c in items):
        total = sum(len(c) for _n, _no, c in items)
        if total > MAX_INLINE_CSV:
            return {"ok": False, "error": (
                f"capture is {total/1e6:.0f} MB — too large to analyse through "
                "the browser. Process it server-side with the streaming CLI and "
                "upload the resulting report.json here:\n"
                "  tinc-flow-analyzer -j 4 -f json -o report.json yourcapture.csv")}
        analysis, stats = flowcsv.analyze_flow_texts(items)
        data = flowcsv.to_dict(analysis, stats)
        return {"ok": True, "mode": "flow", "data": data,
                "summaryText": flowcsv.render_summary(analysis, stats),
                "exports": _flow_exports(analysis)}

    # 3) tinc VPN logs (the original input type).
    host_map = payload.get("hostMap") or None
    year = int(payload.get("year") or DEFAULT_YEAR)
    subnet_dump = payload.get("subnetDump")
    subnet_dump_texts = [subnet_dump] if subnet_dump else None
    analysis, stats = analyze_texts(
        items, host_map=host_map, year=year, subnet_dump_texts=subnet_dump_texts)
    return {
        "ok": True,
        "mode": "tinc",
        "stats": stats,
        "data": reporter.to_dict(analysis, stats),
        "summaryText": reporter.render_summary(analysis, stats),
        "exports": {
            "flows_csv": reporter.render_csv(analysis),
            "policies_csv": reporter.render_policies_csv(analysis),
            "dot": reporter.render_dot(analysis),
        },
    }


def _read_text(name: str) -> Optional[str]:
    path = os.path.join(SAMPLES_DIR, name)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _read_samples() -> list:
    """Return ready-to-analyse sample payloads for the portal's demo button.

    Primary sample is the tshark packet-capture CSV (the real use case); the
    tinc log sample is offered as a secondary entry.
    """
    samples = []
    csv_text = _read_text("network.csv")
    if csv_text is not None:
        samples.append({"label": "packet capture (tshark CSV)",
                        "files": [{"name": "network.csv", "node": "",
                                   "content": csv_text}], "subnetDump": ""})
    tinc_files = []
    try:
        names = sorted(n for n in os.listdir(SAMPLES_DIR) if n.endswith(".log"))
    except OSError:
        names = []
    for name in names:
        text = _read_text(name)
        if text is not None:
            tinc_files.append({"name": name, "node": "", "content": text})
    if tinc_files:
        samples.append({"label": "tinc VPN logs",
                        "files": tinc_files,
                        "subnetDump": _read_text("dump_subnets.txt") or ""})
    return samples


# --- live packet capture (opt-in, server-side tshark) ----------------------

_IFACE_RE = re.compile(r"^[A-Za-z0-9._:@{}\\-]{1,48}$")


def _tshark_argv(iface: str, capture_filter: str = "") -> list:
    """Fixed, safe argv (no shell). Only the validated iface + BPF filter vary."""
    argv = ["tshark", "-i", iface, "-l", "-n"]
    if capture_filter:
        argv += ["-f", capture_filter]   # BPF; entries are IP/CIDR-validated
    argv += ["-T", "fields", "-E", "header=y", "-E", "separator=,",
             "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "udp.srcport", "-e", "udp.dstport",
             "-e", "tcp.flags", "-e", "ip.proto", "-e", "frame.len"]
    return argv


def _list_interfaces() -> list:
    if not shutil.which("tshark"):
        return []
    try:
        out = subprocess.run(["tshark", "-D"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
    except Exception:
        return []
    ifaces = []
    for line in out.stdout.splitlines():
        m = re.match(r"\s*\d+\.\s+(\S+)", line)
        if m:
            ifaces.append(m.group(1))
    return ifaces


class LiveCapture:
    """Runs tshark in a background thread and aggregates packets live.

    The aggregation core is identical to the batch analyzer, so memory stays
    bounded by network cardinality. ``feed_lines`` lets tests drive it without
    tshark; ``start_tshark`` is the real entry point.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        self.analysis = FlowAnalysis()
        self.running = False
        self.error = None
        self.iface = None
        self.proc = None
        self.thread = None
        self._stop = False
        self.start_time = None
        self._last_t = None
        self._last_p = 0

    def is_running(self) -> bool:
        with self._lock:
            return self.running

    def _start(self, factory, iface):
        with self._lock:
            if self.running:
                return False, "capture already running"
            self.reset()
            self.running = True
            self.iface = iface
            self.start_time = time.time()
            self._last_t = self.start_time
        self.thread = threading.Thread(target=self._run, args=(factory,), daemon=True)
        self.thread.start()
        return True, None

    def start_tshark(self, iface, capture_filter=""):
        def factory():
            self.proc = subprocess.Popen(
                _tshark_argv(iface, capture_filter), stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, universal_newlines=True, bufsize=1)
            return self.proc.stdout
        return self._start(factory, iface)

    def _run(self, factory):
        try:
            source = factory()
        except Exception as exc:  # pragma: no cover - depends on tshark
            with self._lock:
                self.error = str(exc)
                self.running = False
            return
        try:
            for rec in iter_flow_records(source):
                if self._stop:
                    break
                with self._lock:
                    self.analysis.add_record(rec)
        except Exception as exc:  # pragma: no cover
            with self._lock:
                self.error = str(exc)
        finally:
            self._terminate()
            with self._lock:
                self.running = False

    def feed_lines(self, lines):
        """Synchronously ingest CSV lines (used by tests / simulation)."""
        for rec in iter_flow_records(lines):
            with self._lock:
                self.analysis.add_record(rec)

    def _terminate(self):
        p = self.proc
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except Exception:  # pragma: no cover
                pass

    def stop(self):
        self._stop = True
        self._terminate()
        t = self.thread
        if t is not None:
            t.join(timeout=2)
        with self._lock:
            self.running = False
        return True

    def snapshot(self, top=25) -> dict:
        with self._lock:
            data = to_dict(self.analysis)
            running, err, iface = self.running, self.error, self.iface
            pkts = self.analysis.packets
            now = time.time()
            elapsed = (now - self.start_time) if self.start_time else 0.0
            dt = (now - self._last_t) if self._last_t else 0.0
            pps = (pkts - self._last_p) / dt if dt > 0 else 0.0
            self._last_t, self._last_p = now, pkts
        for key in ("conversations", "hosts", "services", "subnet_matrix"):
            data[key] = data[key][:top]
        return {"running": running, "error": err, "iface": iface,
                "elapsed": round(elapsed, 1), "pps": round(pps, 1), "data": data}

    def data_only(self):
        """to_dict of the current aggregate (no pps side effects) for snapshots."""
        with self._lock:
            return to_dict(self.analysis)

    def brief(self):
        with self._lock:
            return {"running": self.running, "packets": self.analysis.packets,
                    "iface": self.iface, "error": self.error,
                    "elapsed": round((time.time() - self.start_time), 1)
                    if self.start_time else 0.0}

    def reset_data(self):
        """Drop the accumulated aggregate while keeping capture running (frees
        memory held by host/conversation cardinality)."""
        with self._lock:
            self.analysis = FlowAnalysis()
            self._last_p = 0
        return True

    def export(self, fmt: str):
        with self._lock:
            d = to_dict(self.analysis)
        if fmt == "conversations":
            return flowcsv.render_conversations_csv(d), "text/csv"
        if fmt == "policies":
            return flowcsv.render_policies_csv(d), "text/csv"
        if fmt == "hosts":
            return flowcsv.render_hosts_csv(d), "text/csv"
        if fmt == "dot":
            return flowcsv.render_dot(d), "text/vnd.graphviz"
        if fmt == "json":
            return json.dumps(d, ensure_ascii=False, indent=2), "application/json"
        return None, None


class ScanController(object):
    """Manage the standalone scan backend (a detached process) and read its
    live.json. Because the scan runs in its own process, restarting/upgrading
    the portal does not stop it — the portal just reconnects by reading the file.
    """

    STALE_SECONDS = 12

    def __init__(self, out_dir):
        self.out_dir = out_dir

    def _live_path(self):
        return os.path.join(self.out_dir, "live.json")

    def _read(self):
        try:
            with open(self._live_path(), "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def is_running(self):
        d = self._read()
        if not d or not d.get("running"):
            return False
        if time.time() - float(d.get("heartbeat", 0)) > self.STALE_SECONDS:
            return False        # backend died without a clean final write
        pid = d.get("pid")
        if pid:
            try:
                os.kill(int(pid), 0)
            except (OSError, ValueError):
                return False
        return True

    def start(self, iface, capture_filter, resume=True):
        if self.is_running():
            return False, "이미 캡처 중입니다 (백엔드 실행 중)"
        os.makedirs(self.out_dir, exist_ok=True)
        argv = [sys.executable, "-m", "tinc_route_analyzer.scan",
                "--iface", iface, "--out", self.out_dir]
        if capture_filter:
            argv += ["--filter", capture_filter]
        if resume:
            argv += ["--resume"]
        try:
            log = open(os.path.join(self.out_dir, "scan.log"), "ab")
            subprocess.Popen(argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                             start_new_session=True, close_fds=True)
        except OSError as exc:
            return False, "스캔 백엔드 시작 실패: %s" % exc
        return True, None

    def _signal(self, sig):
        d = self._read()
        pid = d and d.get("pid")
        if pid:
            try:
                os.kill(int(pid), sig)
                return True
            except (OSError, ValueError):
                return False
        return False

    def stop(self):
        self._signal(signal.SIGTERM)
        return True

    def reset(self):
        if hasattr(signal, "SIGUSR1"):
            self._signal(signal.SIGUSR1)
        return True

    def data(self):
        """Full aggregate dict (for persistence snapshots / exports)."""
        d = self._read()
        return (d and d.get("data")) or to_dict(FlowAnalysis())

    def snapshot(self, top=25):
        d = self._read()
        running = self.is_running()
        data = (d and d.get("data")) or to_dict(FlowAnalysis())
        for key in ("conversations", "hosts", "services", "subnet_matrix"):
            if isinstance(data.get(key), list):
                data[key] = data[key][:top]
        if isinstance(data.get("activity"), dict) and isinstance(data["activity"].get("hosts"), list):
            data["activity"]["hosts"] = data["activity"]["hosts"][:top]
        now = time.time()
        started = float(d.get("started", now)) if d else now
        return {"running": running, "iface": (d or {}).get("iface"),
                "error": (d or {}).get("error") or None,
                "elapsed": round(now - started, 1) if d else 0.0,
                "pps": (d or {}).get("pps", 0.0), "data": data}

    def brief(self):
        d = self._read()
        now = time.time()
        return {"running": self.is_running(),
                "packets": (d or {}).get("packets", 0), "iface": (d or {}).get("iface"),
                "error": (d or {}).get("error"),
                "elapsed": round(now - float((d or {}).get("started", now)), 1) if d else 0.0}

    def export(self, fmt):
        d = self.data()
        if fmt == "conversations":
            return flowcsv.render_conversations_csv(d), "text/csv"
        if fmt == "policies":
            return flowcsv.render_policies_csv(d), "text/csv"
        if fmt == "hosts":
            return flowcsv.render_hosts_csv(d), "text/csv"
        if fmt == "dot":
            return flowcsv.render_dot(d), "text/vnd.graphviz"
        if fmt == "json":
            return json.dumps(d, ensure_ascii=False, indent=2), "application/json"
        return None, None


_CAPTURE_ENABLED = False
_SCAN = ScanController(persistence.DEFAULT_DIR)
_PERSIST = persistence.Persistence(lambda: _SCAN.data())
# Last flow result the user viewed, stashed so the full-page topology can load it.
_LAST_FLOW = {"data": None}
# repo root = the directory that contains the tinc_route_analyzer package
_CODE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_UPDATER = updater.UpdateManager(lambda: version_info()["version"], _CODE_DIR)


def _schedule_restart(delay=0.8):
    """Re-exec the portal shortly (after the HTTP response is flushed)."""
    def _do():
        time.sleep(delay)
        try:
            updater.restart_process()      # replaces this process (does not return)
        except Exception as exc:           # pragma: no cover
            print("[update] restart thread error: %s" % exc, file=sys.stderr, flush=True)
    threading.Thread(target=_do, daemon=True).start()

# --- capture exclude (IP / subnet) -----------------------------------------

_CAPTURE_CFG_PATH = os.path.join(persistence.DEFAULT_DIR, "capture.json")
_IPV4_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")


def _valid_exclude(entry):
    return bool(_IPV4_HOST_RE.match(entry) or _CIDR_RE.match(entry))


def _build_capture_filter(excludes):
    """Build a BPF filter that drops the given hosts/subnets (validated)."""
    terms = []
    for e in excludes:
        e = (e or "").strip()
        if _CIDR_RE.match(e):
            terms.append("net " + e)
        elif _IPV4_HOST_RE.match(e):
            terms.append("host " + e)
    return ("not (" + " or ".join(terms) + ")") if terms else ""


def _load_capture_cfg():
    try:
        with open(_CAPTURE_CFG_PATH, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        if isinstance(cfg, dict) and isinstance(cfg.get("exclude"), list):
            return {"exclude": [str(x) for x in cfg["exclude"]],
                    "resume": bool(cfg.get("resume", True))}
    except (OSError, ValueError):
        pass
    return {"exclude": [], "resume": True}   # resume ON by default


def _save_capture_cfg(cfg):
    try:
        os.makedirs(persistence.DEFAULT_DIR, exist_ok=True)
        with open(_CAPTURE_CFG_PATH, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
    except OSError:
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "tinc-route-analyzer-portal"

    # -- helpers ------------------------------------------------------------

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _serve_static(self, rel: str) -> None:
        # Whitelist by basename to prevent path traversal.
        safe = os.path.basename(rel) or "index.html"
        path = os.path.join(STATIC_DIR, safe)
        if not os.path.isfile(path):
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        ext = os.path.splitext(path)[1]
        with open(path, "rb") as fh:
            body = fh.read()
        self._send(200, body, _CONTENT_TYPES.get(ext, "application/octet-stream"))

    # -- routes -------------------------------------------------------------

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/index.html":
            self._serve_static("index.html")
        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
        elif path == "/api/sample":
            self._send_json({"ok": True, "samples": _read_samples()})
        elif path == "/api/health":
            self._send_json({"ok": True})
        elif path == "/api/version":
            v = version_info()
            v["ok"] = True
            self._send_json(v)
        elif path == "/api/live/status":
            self._send_json({"ok": True, "mode": "flow", "live": True,
                             "captureEnabled": _CAPTURE_ENABLED, **_SCAN.snapshot()})
        elif path == "/api/live/interfaces":
            self._send_json({"ok": True, "enabled": _CAPTURE_ENABLED,
                             "interfaces": _list_interfaces()})
        elif path == "/api/live/export":
            fmt = (parse_qs(parsed.query).get("fmt") or ["json"])[0]
            text, ctype = _SCAN.export(fmt)
            if text is None:
                self._send_json({"ok": False, "error": "unknown export format"}, 400)
                return
            ext = "json" if fmt == "json" else ("dot" if fmt == "dot" else "csv")
            body = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="live_{fmt}.{ext}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/sysstatus":
            cfg = _PERSIST.get_config()
            self._send_json({
                "ok": True,
                "system": persistence.system_stats(cfg["save_dir"]),
                "capture": _SCAN.brief(),
                "persist": _PERSIST.status(),
                "captureEnabled": _CAPTURE_ENABLED,
            })
        elif path == "/api/persist/config":
            self._send_json({"ok": True, "config": _PERSIST.get_config()})
        elif path == "/api/persist/files":
            save_dir = _PERSIST.get_config()["save_dir"]
            self._send_json({"ok": True, "dir": save_dir,
                             "files": persistence.list_files(save_dir)})
        elif path == "/api/persist/file":
            q = parse_qs(parsed.query)
            name = (q.get("name") or [""])[0]
            n = int((q.get("lines") or ["100"])[0] or 100)
            save_dir = _PERSIST.get_config()["save_dir"]
            lines = persistence.head_file(save_dir, name, max(1, min(2000, n)))
            if lines is None:
                self._send_json({"ok": False, "error": "파일을 찾을 수 없습니다"}, 404)
            else:
                self._send_json({"ok": True, "name": name, "lines": lines})
        elif path == "/api/last":
            self._send_json({"ok": True, "data": _LAST_FLOW["data"]})
        elif path == "/api/capture/config":
            self._send_json({"ok": True, **_load_capture_cfg()})
        elif path == "/api/update/status":
            self._send_json({"ok": True, **_UPDATER.status()})
        elif path == "/api/update/config":
            self._send_json({"ok": True, "config": _UPDATER.get_config()})
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    do_HEAD = do_GET

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length < 0 or length > MAX_BODY:
            return None
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return None

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/analyze":
            payload = self._read_json_body()
            if payload is None:
                self._send_json({"ok": False, "error": "invalid request body"}, 400)
                return
            try:
                result = analyze_payload(payload)
            except Exception as exc:  # pragma: no cover - defensive
                self._send_json({"ok": False, "error": f"analysis failed: {exc}"}, 500)
                return
            self._send_json(result, 200 if result.get("ok") else 400)
        elif path == "/api/live/start":
            self._live_start()
        elif path == "/api/live/stop":
            _SCAN.stop()
            self._send_json({"ok": True, "running": False})
        elif path == "/api/live/reset":
            _SCAN.reset()
            self._send_json({"ok": True})
        elif path == "/api/last":
            payload = self._read_json_body() or {}
            _LAST_FLOW["data"] = payload.get("data")
            self._send_json({"ok": True})
        elif path == "/api/persist/config":
            payload = self._read_json_body()
            if payload is None:
                self._send_json({"ok": False, "error": "invalid request body"}, 400)
                return
            try:
                cfg = _PERSIST.set_config(payload)
            except OSError as exc:
                self._send_json({"ok": False,
                                 "error": "저장 위치를 쓸 수 없습니다: %s" % exc}, 400)
                return
            self._send_json({"ok": True, "config": cfg})
        elif path == "/api/capture/config":
            payload = self._read_json_body() or {}
            raw = payload.get("exclude") or []
            cleaned, bad = [], []
            for e in raw:
                e = str(e).strip()
                if not e:
                    continue
                (cleaned if _valid_exclude(e) else bad).append(e)
            if bad:
                self._send_json({"ok": False,
                                 "error": "유효하지 않은 항목(IP 또는 CIDR): " + ", ".join(bad)}, 400)
                return
            resume = bool(payload.get("resume", True))
            _save_capture_cfg({"exclude": cleaned, "resume": resume})
            self._send_json({"ok": True, "exclude": cleaned, "resume": resume,
                             "filter": _build_capture_filter(cleaned)})
        elif path == "/api/update/config":
            payload = self._read_json_body() or {}
            self._send_json({"ok": True, "config": _UPDATER.set_config(payload)})
        elif path == "/api/update/check":
            self._send_json(_UPDATER.check())
        elif path == "/api/update/apply":
            res = _UPDATER.apply()
            # If the user enabled auto-restart, applying also restarts (one click).
            if res.get("ok") and _UPDATER.get_config().get("auto_restart"):
                res["restarting"] = True
                _schedule_restart()
            self._send_json(res)
        elif path == "/api/update/restart":
            # Respond first, then re-exec the process shortly after.
            self._send_json({"ok": True, "restarting": True})
            _schedule_restart()
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def _live_start(self):
        if not _CAPTURE_ENABLED:
            self._send_json({"ok": False, "error": (
                "실시간 캡처가 비활성화되어 있습니다. 서버를 '--enable-capture' 로 "
                "실행하세요 (tshark + 캡처 권한 필요).")}, 403)
            return
        payload = self._read_json_body() or {}
        iface = (payload.get("iface") or "").strip()
        if not _IFACE_RE.match(iface):
            self._send_json({"ok": False, "error": "유효하지 않은 인터페이스 이름"}, 400)
            return
        if not shutil.which("tshark"):
            self._send_json({"ok": False, "error": "서버에 tshark가 설치되어 있지 않습니다."}, 400)
            return
        cfg = _load_capture_cfg()
        capfilter = _build_capture_filter(cfg.get("exclude", []))
        ok, err = _SCAN.start(iface, capfilter, cfg.get("resume", True))
        self._send_json({"ok": ok, "error": err, "running": _SCAN.is_running(),
                         "filter": capfilter, "resume": cfg.get("resume", True)},
                        200 if ok else 409)

    def log_message(self, fmt, *args):  # keep the console quiet but informative
        print(f"[portal] {self.address_string()} {fmt % args}")


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host if host != '0.0.0.0' else 'localhost'}:{port}/"
    print(f"tinc route analyzer portal running at {url}")
    print(f"live packet capture: {'ENABLED' if _CAPTURE_ENABLED else 'disabled'}"
          + ("" if _CAPTURE_ENABLED else " (start with --enable-capture)"))
    _PERSIST.start()
    _UPDATER.start()
    print(f"snapshot store: {_PERSIST.get_config()['save_dir']} "
          "(configure cadence/path in the portal)")
    print("press Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        # NB: do NOT stop the scan here — it runs as its own backend process so
        # it keeps capturing across a portal restart/upgrade.
        httpd.server_close()


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(
        prog="tinc-route-analyzer-web",
        description="Launch the tinc route analyzer web portal.")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default: 127.0.0.1; use 0.0.0.0 to expose)")
    p.add_argument("--port", type=int, default=8080, help="port (default: 8080)")
    p.add_argument("--enable-capture", action="store_true",
                   help="enable live packet-capture endpoints (runs tshark "
                        "server-side; requires tshark + capture privileges)")
    args = p.parse_args(argv)
    global _CAPTURE_ENABLED
    _CAPTURE_ENABLED = args.enable_capture
    run(args.host, args.port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
