"""A dependency-free web portal for the tinc route analyzer.

The browser reads the log files locally and POSTs their text content as JSON,
so the server never has to parse multipart uploads — it just runs the existing
analyzer and returns structured results.  Everything (HTML/CSS/JS) is served
from disk with no external CDN, so the portal works fully offline / air-gapped.

Run with::

    python3 -m tinc_route_analyzer.web --port 8080
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .. import flowcsv, reporter
from ..analyzer import analyze_texts
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

    # 1) pre-aggregated flow report.json -> visualise as-is (no re-analysis).
    for _name, _node, content in items:
        report = _try_flow_report(content)
        if report is not None:
            return {"ok": True, "mode": "flow", "fromReport": True,
                    "data": report,
                    "summaryText": flowcsv.render_summary(report),
                    "exports": _flow_exports(report)}

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
        path = self.path.split("?", 1)[0]
        if path == "/" or path == "/index.html":
            self._serve_static("index.html")
        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
        elif path == "/api/sample":
            self._send_json({"ok": True, "samples": _read_samples()})
        elif path == "/api/health":
            self._send_json({"ok": True})
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    do_HEAD = do_GET

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/api/analyze":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send_json({"ok": False, "error": "invalid request size"}, 400)
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "invalid JSON body"}, 400)
            return
        try:
            result = analyze_payload(payload)
        except Exception as exc:  # pragma: no cover - defensive
            self._send_json({"ok": False, "error": f"analysis failed: {exc}"}, 500)
            return
        self._send_json(result, 200 if result.get("ok") else 400)

    def log_message(self, fmt, *args):  # keep the console quiet but informative
        print(f"[portal] {self.address_string()} {fmt % args}")


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host if host != '0.0.0.0' else 'localhost'}:{port}/"
    print(f"tinc route analyzer portal running at {url}")
    print("press Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(
        prog="tinc-route-analyzer-web",
        description="Launch the tinc route analyzer web portal.")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default: 127.0.0.1; use 0.0.0.0 to expose)")
    p.add_argument("--port", type=int, default=8080, help="port (default: 8080)")
    args = p.parse_args(argv)
    run(args.host, args.port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
