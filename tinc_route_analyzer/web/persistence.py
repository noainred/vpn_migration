"""Periodic persistence of the live aggregate + process/disk resource stats.

Standard-library only (no psutil), Python 3.6+:
  * CPU%  -> resource.getrusage (utime+stime) sampled between polls
  * RSS   -> /proc/self/status VmRSS (Linux) with a resource fallback
  * disk  -> shutil.disk_usage
  * saved -> os.listdir + os.path.getsize of the snapshot files

The live capture aggregate is written to disk at minute/hour/day cadences so a
long-running capture leaves a durable, bounded record; the dashboard exposes
CPU/RSS/disk/file-size so memory growth or a filling disk is visible early.
"""

import json
import gzip
import os
import shutil
import threading
import re
import socket
import time
from datetime import datetime

try:
    import resource  # Unix only; absent on Windows
except ImportError:  # pragma: no cover
    resource = None

DEFAULT_DIR = os.path.join(os.getcwd(), "portal_data")
_GRANS = ("minute", "hour", "day")
_KEYFMT = {"minute": "%Y-%m-%d_%H%M", "hour": "%Y-%m-%d_%H", "day": "%Y-%m-%d"}
_PREFIX = {"minute": "flow_min", "hour": "flow_hour", "day": "flow_day"}
# snapshot tokens used to recognise our files even with a host prefix
_TOKENS = tuple(p + "_" for p in _PREFIX.values())   # ("flow_min_", "flow_hour_", "flow_day_")


def hostname_label(override=""):
    """Sanitised host label for snapshot filenames (override wins, else hostname)."""
    raw = (override or "").strip() or socket.gethostname() or "host"
    return re.sub(r"[^A-Za-z0-9._-]", "-", raw)[:40] or "host"


def is_snapshot(name):
    """A snapshot file, with or without a '<host>_' prefix."""
    return (name.endswith(".json") or name.endswith(".json.gz")) \
        and any(t in name for t in _TOKENS)

_cpu_sampler = {"t": None, "cpu": None}


def _cpu_percent():
    """Process CPU% since the previous call (0 on the first call)."""
    if resource is None:
        return 0.0
    ru = resource.getrusage(resource.RUSAGE_SELF)
    cpu = ru.ru_utime + ru.ru_stime
    now = time.time()
    last_t, last_c = _cpu_sampler["t"], _cpu_sampler["cpu"]
    _cpu_sampler["t"], _cpu_sampler["cpu"] = now, cpu
    if last_t is None or now <= last_t:
        return 0.0
    return round((cpu - last_c) / (now - last_t) * 100.0, 1)


def _rss_bytes():
    """Current resident memory of this process in bytes."""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024  # kB -> bytes
    except (OSError, ValueError, IndexError):
        pass
    if resource is not None:
        # ru_maxrss is kB on Linux (peak); a usable fallback.
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    return 0


def _peak_rss_bytes():
    if resource is not None:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    return 0


def list_files(save_dir):
    """All snapshot files in ``save_dir`` (newest first)."""
    _total, files = _saved_files(save_dir)
    return files


def head_file(save_dir, name, n=100):
    """Return the first ``n`` lines of a saved snapshot (for save verification).

    ``name`` must be a bare snapshot filename inside ``save_dir`` (no path
    traversal). Transparently decompresses ``.gz``.
    """
    base = os.path.basename(name or "")
    if base != name or not is_snapshot(base):
        return None
    path = os.path.join(save_dir, base)
    if not os.path.isfile(path):
        return None
    opener = gzip.open if base.endswith(".gz") else open
    lines = []
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= n:
                    break
                lines.append(line.rstrip("\n")[:1000])  # cap very long lines
    except OSError:
        return None
    return lines


def _saved_files(save_dir):
    total = 0
    files = []
    try:
        names = os.listdir(save_dir)
    except OSError:
        return 0, []
    for name in names:
        if not is_snapshot(name):
            continue
        fp = os.path.join(save_dir, name)
        try:
            st = os.stat(fp)
        except OSError:
            continue
        files.append({
            "name": name, "bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
        })
        total += st.st_size
    files.sort(key=lambda f: f["mtime"], reverse=True)
    return total, files


def system_stats(save_dir):
    """Return CPU/memory, disk free space for ``save_dir`` and saved-file size."""
    probe = save_dir if os.path.isdir(save_dir) else (os.path.dirname(save_dir) or ".")
    try:
        du = shutil.disk_usage(probe)
        disk = {"path": probe, "total": du.total, "used": du.used, "free": du.free,
                "percent_used": round(du.used / du.total * 100, 1) if du.total else 0}
    except OSError:
        disk = {"path": probe, "total": 0, "used": 0, "free": 0, "percent_used": 0}
    total, files = _saved_files(save_dir)
    return {
        "cpu_percent": _cpu_percent(),
        "rss_bytes": _rss_bytes(),
        "peak_rss_bytes": _peak_rss_bytes(),
        "disk": disk,
        "saved": {"dir": save_dir, "bytes": total, "count": len(files),
                  "recent": files[:12]},
    }


class Persistence(object):
    """Background scheduler that snapshots the live aggregate to disk."""

    def __init__(self, snapshot_fn):
        # snapshot_fn() -> a flow report dict (flowcsv.to_dict) or None.
        self.snapshot_fn = snapshot_fn
        self._lock = threading.Lock()
        self.config = {"save_dir": DEFAULT_DIR, "minute": False, "hour": False,
                       "day": False, "retention": 0, "compress": False,
                       "host_label": ""}   # "" -> use the machine hostname
        self.last = {"minute": None, "hour": None, "day": None}
        self.last_paths = {"minute": None, "hour": None, "day": None}
        self._stop = False
        self.thread = None
        self._load_config()

    # -- config -------------------------------------------------------------

    def get_config(self):
        with self._lock:
            return dict(self.config)

    def set_config(self, cfg):
        save_dir = (cfg.get("save_dir") or "").strip() or DEFAULT_DIR
        save_dir = os.path.abspath(os.path.expanduser(save_dir))
        os.makedirs(save_dir, exist_ok=True)
        # confirm it is writable (raises on failure -> surfaced to the caller)
        probe = os.path.join(save_dir, ".portal_write_test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        with self._lock:
            self.config = {
                "save_dir": save_dir,
                "minute": bool(cfg.get("minute")),
                "hour": bool(cfg.get("hour")),
                "day": bool(cfg.get("day")),
                "retention": max(0, int(cfg.get("retention") or 0)),
                "compress": bool(cfg.get("compress")),
                "host_label": (cfg.get("host_label") or "").strip(),
            }
        self._save_config()
        return self.get_config()

    def status(self):
        with self._lock:
            return {"config": dict(self.config), "last": dict(self.last),
                    "last_paths": dict(self.last_paths)}

    # -- scheduler ----------------------------------------------------------

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop = True

    def _run(self):
        while not self._stop:
            try:
                self._tick()
            except Exception:  # pragma: no cover - never kill the thread
                pass
            time.sleep(5)

    def _tick(self):
        cfg = self.get_config()
        if not (cfg["minute"] or cfg["hour"] or cfg["day"]):
            return
        now = datetime.now()
        data = None
        for gran in _GRANS:
            if not cfg[gran]:
                continue
            key = now.strftime(_KEYFMT[gran])
            if self.last[gran] == key:
                continue
            if data is None:
                data = self.snapshot_fn()
                if not data or data.get("meta", {}).get("packets", 0) <= 0:
                    return  # nothing collected yet; try again next tick
            path = self._write(cfg["save_dir"], gran, key, data,
                               cfg.get("compress"), cfg.get("host_label"))
            with self._lock:
                self.last[gran] = key
                self.last_paths[gran] = path
            self._retain(cfg["save_dir"], gran, cfg["retention"])

    def _write(self, save_dir, gran, key, data, compress=False, host_label=""):
        os.makedirs(save_dir, exist_ok=True)
        ext = ".json.gz" if compress else ".json"
        host = hostname_label(host_label)
        # "<host>_flow_<gran>_<key>.json" so files from different servers don't
        # collide when collected into one folder for merging.
        path = os.path.join(save_dir, "%s_%s_%s%s" % (host, _PREFIX[gran], key, ext))
        tmp = path + ".tmp"
        # indent=2 so files stay human-readable for the "first 100 lines" preview;
        # gzip handles the size when 압축 저장 is on.
        if compress:
            with gzip.open(tmp, "wt", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        else:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)   # atomic
        return path

    def _retain(self, save_dir, gran, keep):
        if not keep or keep <= 0:
            return
        try:
            names = sorted(n for n in os.listdir(save_dir)
                           if (_PREFIX[gran] + "_") in n and is_snapshot(n))
        except OSError:
            return
        for name in names[:-keep]:
            try:
                os.remove(os.path.join(save_dir, name))
            except OSError:
                pass

    # -- config file --------------------------------------------------------

    def _config_path(self):
        return os.path.join(DEFAULT_DIR, "config.json")

    def _save_config(self):
        try:
            os.makedirs(DEFAULT_DIR, exist_ok=True)
            with open(self._config_path(), "w", encoding="utf-8") as fh:
                json.dump(self.config, fh)
        except OSError:  # pragma: no cover
            pass

    def _load_config(self):
        try:
            with open(self._config_path(), "r", encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, ValueError):
            return
        if isinstance(saved, dict):
            for k in list(self.config):
                if k in saved:
                    self.config[k] = saved[k]
