"""tinc_route_analyzer — analyse tinc VPN logs to discover node-to-node traffic.

The package parses tinc VPN log files collected from several machines (Linux,
Windows, macOS, ...), reconstructs *which node talked to which node*, the
routing/relay path that was used, and the subnets each node owns.  The result
is the information you need to recreate the equivalent connectivity and
firewall policy when migrating from tinc to an NSX based VPN.

Public API:
    parse_line / iter_events          -> tinc_route_analyzer.parser
    Analysis / analyze_files          -> tinc_route_analyzer.analyzer
    render_* report helpers           -> tinc_route_analyzer.reporter
"""

from .models import EventType, LogEvent, FlowStats, NodeInfo
from .parser import parse_line, iter_events
from .analyzer import Analysis, analyze_files

__all__ = [
    "EventType",
    "LogEvent",
    "FlowStats",
    "NodeInfo",
    "parse_line",
    "iter_events",
    "Analysis",
    "analyze_files",
    "version_info",
]

__version__ = "1.3.0"


def version_info():
    """Return ``{'version', 'build', 'date'}`` for display in the portal.

    ``build``/``date`` come from a BUILD stamp filled in at release time by
    ``git archive`` (export-subst), or from git in a dev checkout — so the
    portal shows exactly which commit is deployed, not just a static version.
    """
    import os

    info = {"version": __version__, "build": "", "date": ""}
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        with open(os.path.join(root, "BUILD"), "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
        if raw and "$Format" not in raw:   # substituted by git archive
            parts = raw.split("|")
            info["build"] = parts[0].strip()
            if len(parts) > 1:
                info["date"] = parts[1].strip()
    except OSError:
        pass
    if not info["build"]:                  # dev checkout fallback
        try:
            import subprocess
            out = subprocess.check_output(
                ["git", "-C", root, "log", "-1", "--format=%h|%cI"],
                stderr=subprocess.DEVNULL, universal_newlines=True).strip()
            parts = out.split("|")
            info["build"] = parts[0]
            if len(parts) > 1:
                info["date"] = parts[1]
        except Exception:
            pass
    return info
