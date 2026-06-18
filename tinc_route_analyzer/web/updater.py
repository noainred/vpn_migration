"""Self-upgrade — apply a newer packaged version (watch folder or remote bundle).

Ported from the isilon_good upgrade module and adapted to this toolkit. Watches
a folder for ``tinc_route_analyzer-<version>.tar.gz/.zip`` (or checks a remote
``versions.json``); if it is newer than the running version, it swaps the
package in (backing up the old one) and re-execs the process. Standard library
only.

Safety: opt-in (disabled when unconfigured), archive validation (package +
version), only-newer applied, path-escape prevention, backup of the old code
(rollback), bounded extraction (no zip/tar bombs).
"""

import io
import json
import os
import re
import shutil
import sys
import tarfile
import threading
import time
import zipfile
import urllib.request
from typing import Dict, Optional, Tuple

PACKAGE = "tinc_route_analyzer"
_ARCHIVE_RE = re.compile(r"tinc_route_analyzer-(\d+)\.(\d+)\.(\d+)\.(?:tar\.gz|tgz|zip)$")
_INIT_VER_RE = re.compile(r"""__version__\s*=\s*["'](\d+)\.(\d+)\.(\d+)["']""")

MAX_BUNDLE_BYTES = 200 * 1024 * 1024
MAX_MEMBERS = 20000


def parse_version(s):
    m = re.match(r"^\s*v?(\d+)\.(\d+)\.(\d+)", str(s or ""))
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(t):
    return ".".join(str(x) for x in t)


def _archive_version(filename):
    m = _ARCHIVE_RE.search(os.path.basename(filename))
    return tuple(int(x) for x in m.groups()) if m else None


def find_newer_archive(watch_dir, current_version):
    """Newest ``tinc_route_analyzer-*`` archive in ``watch_dir`` above current."""
    cur = parse_version(current_version) or (0, 0, 0)
    best = None
    try:
        names = os.listdir(watch_dir)
    except OSError:
        return None
    for name in names:
        v = _archive_version(name)
        if v and v > cur and (best is None or v > best[1]):
            best = (os.path.join(watch_dir, name), v)
    return best


def _accept_member(name):
    """Safe relative path under ``tinc_route_analyzer/`` (or None)."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if PACKAGE not in parts:
        return None
    rel = parts[parts.index(PACKAGE) + 1:]
    if not rel or any(p == ".." for p in rel):
        return None
    return "/".join(rel)


def _members_from_tar(tf):
    out = {}
    total = 0
    for m in tf:
        if not m.isfile():
            continue
        rel = _accept_member(m.name)
        if not rel:
            continue
        if len(out) >= MAX_MEMBERS or total + int(m.size or 0) > MAX_BUNDLE_BYTES:
            raise ValueError("archive too large (or too many members)")
        f = tf.extractfile(m)
        if f is not None:
            data = f.read()
            out[rel] = data
            total += len(data)
    return out


def read_package_members(archive_path):
    """Read ``tinc_route_analyzer/<...>`` files as {relpath: bytes} (bounded)."""
    if archive_path.endswith(".zip"):
        out = {}
        total = 0
        with zipfile.ZipFile(archive_path) as zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                rel = _accept_member(zi.filename)
                if not rel:
                    continue
                if len(out) >= MAX_MEMBERS or total + int(zi.file_size or 0) > MAX_BUNDLE_BYTES:
                    raise ValueError("archive too large (or too many members)")
                data = zf.read(zi)
                out[rel] = data
                total += len(data)
        return out
    with tarfile.open(archive_path, "r:*") as tf:
        return _members_from_tar(tf)


def members_version(members):
    init = members.get("__init__.py")
    if not init:
        return None
    m = _INIT_VER_RE.search(init.decode("utf-8", "replace"))
    return tuple(int(x) for x in m.groups()) if m else None


def apply_package(members, code_dir):
    """Install members to ``code_dir/tinc_route_analyzer/`` (atomic, backup)."""
    code_dir = os.path.abspath(code_dir)
    pkg = os.path.join(code_dir, PACKAGE)
    ts = int(time.time())
    staging = "%s.new.%d" % (pkg, ts)
    backup = "%s.bak.%d" % (pkg, ts)
    shutil.rmtree(staging, ignore_errors=True)
    for rel, data in members.items():
        dst = os.path.join(staging, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as fh:
            fh.write(data)
    had_old = os.path.isdir(pkg)
    if had_old:
        os.replace(pkg, backup)
    try:
        os.replace(staging, pkg)
    except OSError:
        if had_old:
            os.replace(backup, pkg)
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return backup if had_old else ""


def upgrade_from_archive(archive_path, code_dir, current_version):
    try:
        members = read_package_members(archive_path)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        return {"ok": False, "reason": "read failed: %s" % exc}
    new_v = members_version(members)
    if not new_v:
        return {"ok": False, "reason": "archive has no valid tinc_route_analyzer package/version"}
    cur = parse_version(current_version) or (0, 0, 0)
    if new_v <= cur:
        return {"ok": False, "reason": "not newer (%s <= %s)" % (vstr(new_v), vstr(cur)),
                "version": vstr(new_v)}
    try:
        backup = apply_package(members, code_dir)
    except OSError as exc:
        return {"ok": False, "reason": "swap failed: %s" % exc}
    return {"ok": True, "version": vstr(new_v), "from": vstr(cur), "backup": backup}


def code_dir_of(package_file):
    return os.path.dirname(os.path.dirname(os.path.abspath(package_file)))


def restart_process():
    """Re-exec this process (``python -m tinc_route_analyzer.web <args>``)."""
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(sys.executable, [sys.executable, "-m", "tinc_route_analyzer.web"] + sys.argv[1:])


# --- remote version source (versions.json over HTTPS, optional token) -------

_RAW_GH_RE = re.compile(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/(.+)$")
_WWW_GH_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/raw/(.+)$")


def _to_github_api(base):
    m = _RAW_GH_RE.match(base) or _WWW_GH_RE.match(base)
    if not m:
        return base
    owner, repo, rest = m.groups()
    ref, _, dirpath = rest.rpartition("/")
    if not ref or not dirpath:
        return base
    return "https://api.github.com/repos/%s/%s/contents/%s?ref=%s" % (owner, repo, dirpath, ref)


def _resolve_base(base_url, token):
    base = (base_url or "").rstrip("/")
    return _to_github_api(base) if token else base


def _join_url(base, name):
    if "?" in base:
        head, _, query = base.partition("?")
        return head.rstrip("/") + "/" + name + "?" + query
    return base.rstrip("/") + "/" + name


def _auth_request(url, token):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
        if "api.github.com" in url:
            headers["Accept"] = "application/vnd.github.raw"
    return urllib.request.Request(url, headers=headers)


def fetch_remote_versions(base_url, token=None, timeout=10.0):
    url = _join_url(base_url, "versions.json")
    try:
        with urllib.request.urlopen(_auth_request(url, token), timeout=timeout) as r:
            raw = r.read(4 * 1024 * 1024)
        return json.loads(raw.decode("utf-8")), None
    except Exception as exc:  # noqa: BLE001
        return None, "version lookup failed: %s" % exc


def check_remote(base_url, current_version, token=None, timeout=10.0):
    base = _resolve_base(base_url, token)
    data, err = fetch_remote_versions(base, token=token, timeout=timeout)
    cur = parse_version(current_version) or (0, 0, 0)
    out = {"ok": err is None, "current": vstr(cur), "available": False,
           "checked_at": time.time(), "source": _join_url(base, "versions.json")}
    if err:
        out["error"] = err
        return out
    latest = str(data.get("latest") or "")
    lt = parse_version(latest)
    out["latest"] = latest
    out["available"] = bool(lt and lt > cur)
    for v in (data.get("versions") or []):
        if str(v.get("version")) == latest:
            out["tar_gz"] = v.get("tar_gz")
            out["size_bytes"] = v.get("size_bytes")
            if v.get("tar_gz"):
                out["download_url"] = _join_url(base, v["tar_gz"])
            break
    return out


def download_archive(url, dest_dir, token=None, timeout=120.0, max_bytes=MAX_BUNDLE_BYTES):
    name = os.path.basename((url or "").split("?")[0])
    if not _ARCHIVE_RE.search(name):
        return {"ok": False, "reason": "disallowed archive name: %s" % (name or "(none)")}
    try:
        os.makedirs(dest_dir, exist_ok=True)
        with urllib.request.urlopen(_auth_request(url, token), timeout=timeout) as r:
            data = r.read(max_bytes + 1)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": "download failed: %s" % exc}
    if len(data) > max_bytes:
        return {"ok": False, "reason": "download too large (>%d bytes)" % max_bytes}
    dest = os.path.join(dest_dir, name)
    with open(dest, "wb") as fh:
        fh.write(data)
    return {"ok": True, "path": dest, "size": len(data)}


def upgrade_from_remote(base_url, code_dir, current_version, dest_dir, token=None, timeout=120.0):
    info = check_remote(base_url, current_version, token=token, timeout=min(timeout, 15))
    if not info.get("ok"):
        return {"ok": False, "reason": info.get("error", "version check failed"), "check": info}
    if not info.get("available"):
        return {"ok": False, "reason": "already up to date (%s)" % info.get("latest"),
                "check": info, "up_to_date": True}
    if not info.get("download_url"):
        return {"ok": False, "reason": "no download URL", "check": info}
    dl = download_archive(info["download_url"], dest_dir, token=token, timeout=timeout)
    if not dl.get("ok"):
        return {"ok": False, "reason": dl.get("reason"), "check": info}
    res = upgrade_from_archive(dl["path"], code_dir, current_version)
    res["check"] = info
    res["downloaded"] = dl.get("size")
    return res


# --- portal integration: config + background watcher ------------------------

class UpdateManager(object):
    """Opt-in update orchestration for the portal (config + watch thread)."""

    def __init__(self, current_version_fn, code_dir):
        self.current_version_fn = current_version_fn
        self.code_dir = code_dir
        self._lock = threading.Lock()
        self.config = {"enabled": False, "watch_dir": "", "remote_base": "",
                       "token": "", "auto_apply": False, "auto_restart": False}
        self.last = {"checked_at": 0, "available": False, "latest": "", "error": "",
                     "pending_restart": False, "last_apply": ""}
        self._stop = False
        self.thread = None
        self._load()

    def _cfg_path(self):
        return os.path.join(self.code_dir, "portal_data", "update.json")

    def _load(self):
        try:
            with open(self._cfg_path(), "r", encoding="utf-8") as fh:
                saved = json.load(fh)
            if isinstance(saved, dict):
                for k in list(self.config):
                    if k in saved:
                        self.config[k] = saved[k]
        except (OSError, ValueError):
            pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self._cfg_path()), exist_ok=True)
            with open(self._cfg_path(), "w", encoding="utf-8") as fh:
                json.dump(self.config, fh)
        except OSError:
            pass

    def get_config(self):
        with self._lock:
            c = dict(self.config)
        c["has_token"] = bool(c.pop("token", ""))   # never expose the token
        return c

    def set_config(self, cfg):
        with self._lock:
            self.config["enabled"] = bool(cfg.get("enabled"))
            self.config["watch_dir"] = (cfg.get("watch_dir") or "").strip()
            self.config["remote_base"] = (cfg.get("remote_base") or "").strip()
            self.config["auto_apply"] = bool(cfg.get("auto_apply"))
            self.config["auto_restart"] = bool(cfg.get("auto_restart"))
            if "token" in cfg and cfg.get("token") is not None:
                # blank keeps the existing token; a value replaces it.
                t = (cfg.get("token") or "").strip()
                if t:
                    self.config["token"] = t
        self._save()
        return self.get_config()

    def status(self):
        with self._lock:
            last = dict(self.last)
        last["config"] = self.get_config()
        last["current"] = self.current_version_fn()
        return last

    def check(self):
        cur = self.current_version_fn()
        result = {"ok": True, "current": cur, "available": False, "sources": []}
        with self._lock:
            cfg = dict(self.config)
        # local watch folder
        if cfg.get("watch_dir"):
            found = find_newer_archive(cfg["watch_dir"], cur)
            if found:
                result["available"] = True
                result["local"] = {"path": found[0], "version": vstr(found[1])}
        # remote source
        if cfg.get("remote_base"):
            info = check_remote(cfg["remote_base"], cur, token=cfg.get("token") or None)
            result["remote"] = info
            if info.get("available"):
                result["available"] = True
        with self._lock:
            self.last.update({"checked_at": time.time(), "available": result["available"],
                              "latest": (result.get("remote") or {}).get("latest", ""),
                              "error": (result.get("remote") or {}).get("error", "")})
        return result

    def apply(self):
        cur = self.current_version_fn()
        with self._lock:
            cfg = dict(self.config)
        if not cfg.get("enabled"):
            return {"ok": False, "reason": "자동 업데이트가 비활성화되어 있습니다(설정에서 켜세요)."}
        dest = os.path.join(self.code_dir, "portal_data", "updates")
        # 1) local archive
        if cfg.get("watch_dir"):
            found = find_newer_archive(cfg["watch_dir"], cur)
            if found:
                res = upgrade_from_archive(found[0], self.code_dir, cur)
                if res.get("ok"):
                    with self._lock:
                        self.last["pending_restart"] = True
                        self.last["last_apply"] = "%s -> %s (local)" % (res.get("from"), res.get("version"))
                    return res
        # 2) remote
        if cfg.get("remote_base"):
            res = upgrade_from_remote(cfg["remote_base"], self.code_dir, cur, dest,
                                      token=cfg.get("token") or None)
            if res.get("ok"):
                with self._lock:
                    self.last["pending_restart"] = True
                    self.last["last_apply"] = "%s -> %s (remote)" % (res.get("from"), res.get("version"))
            return res
        return {"ok": False, "reason": "감시 폴더/원격 소스가 설정되지 않았습니다."}

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop = True

    def _run(self):
        while not self._stop:
            try:
                with self._lock:
                    enabled = self.config.get("enabled")
                    auto = self.config.get("auto_apply")
                if enabled:
                    res = self.check()
                    if auto and res.get("available"):
                        self.apply()
            except Exception:  # pragma: no cover - never kill the thread
                pass
            time.sleep(60)
