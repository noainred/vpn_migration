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

from .. import reporter
from ..analyzer import analyze_texts
from ..parser import DEFAULT_YEAR

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
# samples/ lives at the repository root, two levels above this package.
SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "samples",
)
MAX_BODY = 256 * 1024 * 1024  # 256 MiB upload guard

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


def analyze_payload(payload: dict) -> dict:
    """Pure analysis entry point used by the HTTP handler (and tests).

    Expected payload::

        {
          "files": [{"name": "...", "node": "", "content": "..."}, ...],
          "subnetDump": "optional tinc dump subnets text",
          "hostMap": {"oshost": "node"},
          "year": 2026
        }
    """
    files = payload.get("files") or []
    if not files:
        return {"ok": False, "error": "no files provided"}

    items = [
        (f.get("name") or "upload.log", (f.get("node") or "").strip() or None,
         f.get("content") or "")
        for f in files
    ]
    host_map = payload.get("hostMap") or None
    year = int(payload.get("year") or DEFAULT_YEAR)
    subnet_dump = payload.get("subnetDump")
    subnet_dump_texts = [subnet_dump] if subnet_dump else None

    analysis, stats = analyze_texts(
        items, host_map=host_map, year=year, subnet_dump_texts=subnet_dump_texts)

    return {
        "ok": True,
        "stats": stats,
        "data": reporter.to_dict(analysis, stats),
        "summaryText": reporter.render_summary(analysis, stats),
        "exports": {
            "flows_csv": reporter.render_csv(analysis),
            "policies_csv": reporter.render_policies_csv(analysis),
            "dot": reporter.render_dot(analysis),
        },
    }


def _read_samples() -> list:
    out = []
    try:
        names = sorted(os.listdir(SAMPLES_DIR))
    except OSError:
        return out
    for name in names:
        if not name.endswith(".log"):
            continue
        path = os.path.join(SAMPLES_DIR, name)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                out.append({"name": name, "node": "", "content": fh.read()})
        except OSError:
            continue
    dump_path = os.path.join(SAMPLES_DIR, "dump_subnets.txt")
    subnet_dump = ""
    if os.path.exists(dump_path):
        try:
            with open(dump_path, "r", encoding="utf-8", errors="replace") as fh:
                subnet_dump = fh.read()
        except OSError:
            subnet_dump = ""
    return [{"files": out, "subnetDump": subnet_dump}]


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
