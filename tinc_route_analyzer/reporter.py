"""Rendering of an :class:`~tinc_route_analyzer.analyzer.Analysis` into reports.

All renderers return strings so the CLI can print them or write them to a
file.  Output formats: human summary, per-node table, communication pairs,
directed flows, routing/relay paths, subnet ownership, CSV, JSON and Graphviz
DOT.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Optional

from .analyzer import Analysis


def _fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.0f}{u}" if u == "B" else f"{f:.1f}{u}"
        f /= 1024
    return f"{n}B"


def _fmt_dt(dt: Optional[datetime]) -> str:
    return dt.isoformat() if dt else "-"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "  (none)\n"
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  " + "  ".join("-" * widths[i] for i in range(len(headers)))
    out = [line, sep]
    for row in rows:
        out.append("  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(out) + "\n"


# --- individual sections ---------------------------------------------------

def render_overview(analysis: Analysis, stats: Optional[dict] = None) -> str:
    n_nodes = len(analysis.nodes)
    n_logged = sum(1 for n in analysis.nodes.values() if n.has_log)
    out = ["tinc VPN traffic analysis", "=" * 60]
    if stats:
        out.append(
            f"parsed {stats.get('events', 0)} events from "
            f"{stats.get('lines', 0)} lines across {stats.get('files', 0)} file(s)"
        )
    out.append(f"nodes discovered : {n_nodes} ({n_logged} with their own logs, "
               f"{n_nodes - n_logged} seen only via peers)")
    out.append(f"communication pairs : {len(analysis.communication_pairs())}")
    out.append(f"relayed (multi-hop) flows : {len(analysis.routed_flows())}")
    out.append(f"subnets mapped : {len(analysis.subnets)}")
    if analysis.first_seen or analysis.last_seen:
        out.append(f"time span : {_fmt_dt(analysis.first_seen)} .. "
                   f"{_fmt_dt(analysis.last_seen)}")
    if analysis.events_without_local:
        out.append(f"note: {analysis.events_without_local} packet line(s) had no "
                   f"identifiable local node (use --node NAME=FILE to fix)")
    return "\n".join(out) + "\n"


def render_nodes(analysis: Analysis) -> str:
    rows = []
    for n in analysis.sorted_nodes():
        rows.append([
            n.name,
            "yes" if n.has_log else "no",
            ", ".join(sorted(n.real_addresses)) or "-",
            ", ".join(sorted(n.subnets)) or "-",
            str(len(n.peers)),
            _fmt_bytes(n.sent_bytes),
            _fmt_bytes(n.recv_bytes),
        ])
    return "Nodes (physical address = VPN tunnel endpoint for NSX)\n" + _table(
        ["node", "log?", "real address(es)", "owned subnet(s)",
         "peers", "tx", "rx"],
        rows,
    )


def render_pairs(analysis: Analysis, top: Optional[int] = None) -> str:
    pairs = analysis.communication_pairs()
    if top:
        pairs = pairs[:top]
    rows = []
    for p in pairs:
        path = "direct" if p["direct_link"] and not p["via"] else (
            "via " + ", ".join(sorted(p["via"])) if p["via"] else "indirect")
        rows.append([
            f"{p['a']} <-> {p['b']}",
            str(p["packets"]),
            _fmt_bytes(p["bytes"]),
            path,
            str(len(p["directions"])),
        ])
    return ("Communication pairs (each pair => one NSX connectivity / firewall policy)\n"
            + _table(["node pair", "packets", "bytes", "path", "dirs"], rows))


def render_flows(analysis: Analysis, top: Optional[int] = None) -> str:
    flows = analysis.sorted_flows()
    if top:
        flows = flows[:top]
    rows = []
    for f in flows:
        rows.append([
            f"{f.src} -> {f.dst}",
            str(f.packets),
            _fmt_bytes(f.bytes),
            f"{f.sent_packets}/{f.recv_packets}",
            str(f.forwarded_packets),
            ", ".join(sorted(f.via)) or "-",
        ])
    return ("Directed flows  (sent/recv = observed at source/destination)\n"
            + _table(["flow", "packets", "bytes", "sent/recv", "fwd", "via"], rows))


def render_routes(analysis: Analysis) -> str:
    out = ["Routing / relay paths (multi-hop traffic that tinc auto-routed)"]
    routed = analysis.routed_flows()
    if not routed:
        out.append("  (no relayed traffic observed — all flows were direct)")
        return "\n".join(out) + "\n"
    rows = []
    for f in routed:
        relays = " -> ".join(sorted(f.via)) if f.via else "?"
        no_tunnel = "" if frozenset((f.src, f.dst)) in analysis.direct_links else \
            "  [no direct tunnel]"
        rows.append([
            f"{f.src} -> {relays} -> {f.dst}",
            str(f.forwarded_packets or f.packets),
            no_tunnel.strip() or "-",
        ])
    out.append(_table(["path", "packets", "note"], rows).rstrip("\n"))
    out.append("")
    out.append("  In tinc these hops are automatic. In NSX you must provide explicit")
    out.append("  connectivity (hub routing or a direct tunnel) for each pair above.")
    return "\n".join(out) + "\n"


def render_subnets(analysis: Analysis) -> str:
    rows = [[subnet, owner] for subnet, owner in
            sorted(analysis.subnets.items(), key=lambda kv: kv[1])]
    return "Subnet ownership (use to build NSX IP Sets / Groups)\n" + _table(
        ["subnet", "owner node"], rows)


def render_summary(analysis: Analysis, stats: Optional[dict] = None,
                   top: Optional[int] = None) -> str:
    """The default human-facing report: everything, in reading order."""
    parts = [
        render_overview(analysis, stats),
        render_nodes(analysis),
        render_pairs(analysis, top=top),
        render_routes(analysis),
        render_subnets(analysis),
    ]
    return "\n".join(parts)


# --- derived policy view (NSX migration) -----------------------------------

def policies(analysis: Analysis) -> list[dict]:
    """Turn observed communication pairs into proposed allow-policies.

    Each policy carries both endpoints' owned subnets and physical addresses,
    so it maps directly onto an NSX firewall rule / IP Set pair.
    """
    out = []
    for p in analysis.communication_pairs():
        a, b = p["a"], p["b"]
        na = analysis.nodes.get(a)
        nb = analysis.nodes.get(b)
        out.append({
            "name": f"allow-{a}-{b}",
            "a": a,
            "b": b,
            "a_subnets": sorted(na.subnets) if na else [],
            "b_subnets": sorted(nb.subnets) if nb else [],
            "a_endpoints": sorted(na.real_addresses) if na else [],
            "b_endpoints": sorted(nb.real_addresses) if nb else [],
            "action": "ALLOW",
            "packets": p["packets"],
            "bytes": p["bytes"],
            "path": ("direct" if p["direct_link"] and not p["via"]
                     else ("via " + ", ".join(sorted(p["via"])) if p["via"]
                           else "indirect")),
            "relayed": bool(p["via"]) or p["forwarded_packets"] > 0,
            "directions": sorted(p["directions"]),
            "first_seen": _fmt_dt(p["first_seen"]),
            "last_seen": _fmt_dt(p["last_seen"]),
        })
    return out


def render_policies(analysis: Analysis) -> str:
    rows = []
    for pol in policies(analysis):
        rows.append([
            pol["name"],
            f"{pol['a']} <-> {pol['b']}",
            ", ".join(pol["a_subnets"]) or "-",
            ", ".join(pol["b_subnets"]) or "-",
            pol["action"],
            str(pol["packets"]),
            _fmt_bytes(pol["bytes"]),
            pol["path"],
        ])
    return ("Collected policies (proposed NSX allow rules)\n" + _table(
        ["policy", "pair", "subnets A", "subnets B", "action",
         "packets", "bytes", "path"], rows))


def render_policies_csv(analysis: Analysis) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["policy", "node_a", "node_b", "a_subnets", "b_subnets",
                "a_endpoints", "b_endpoints", "action", "packets", "bytes",
                "path", "relayed", "first_seen", "last_seen"])
    for pol in policies(analysis):
        w.writerow([
            pol["name"], pol["a"], pol["b"],
            "|".join(pol["a_subnets"]), "|".join(pol["b_subnets"]),
            "|".join(pol["a_endpoints"]), "|".join(pol["b_endpoints"]),
            pol["action"], pol["packets"], pol["bytes"], pol["path"],
            "yes" if pol["relayed"] else "no",
            pol["first_seen"], pol["last_seen"],
        ])
    return buf.getvalue()


# --- machine-readable formats ----------------------------------------------

def render_csv(analysis: Analysis) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["src", "dst", "packets", "bytes", "sent_packets", "sent_bytes",
                "recv_packets", "recv_bytes", "forwarded_packets", "via",
                "first_seen", "last_seen"])
    for f in analysis.sorted_flows():
        w.writerow([
            f.src, f.dst, f.packets, f.bytes, f.sent_packets, f.sent_bytes,
            f.recv_packets, f.recv_bytes, f.forwarded_packets,
            "|".join(sorted(f.via)), _fmt_dt(f.first_seen), _fmt_dt(f.last_seen),
        ])
    return buf.getvalue()


def to_dict(analysis: Analysis, stats: Optional[dict] = None) -> dict:
    def node_dict(n):
        return {
            "name": n.name,
            "has_log": n.has_log,
            "real_addresses": sorted(n.real_addresses),
            "subnets": sorted(n.subnets),
            "peers": sorted(n.peers),
            "direct_links": sorted(n.direct_links),
            "relays_used": sorted(n.relays_used),
            "relayed_for": sorted(n.relayed_for),
            "sent_packets": n.sent_packets,
            "sent_bytes": n.sent_bytes,
            "recv_packets": n.recv_packets,
            "recv_bytes": n.recv_bytes,
            "first_seen": _fmt_dt(n.first_seen),
            "last_seen": _fmt_dt(n.last_seen),
        }

    def flow_dict(f):
        return {
            "src": f.src,
            "dst": f.dst,
            "packets": f.packets,
            "bytes": f.bytes,
            "sent_packets": f.sent_packets,
            "sent_bytes": f.sent_bytes,
            "recv_packets": f.recv_packets,
            "recv_bytes": f.recv_bytes,
            "forwarded_packets": f.forwarded_packets,
            "via": sorted(f.via),
            "first_seen": _fmt_dt(f.first_seen),
            "last_seen": _fmt_dt(f.last_seen),
        }

    def pair_dict(p):
        return {
            "a": p["a"],
            "b": p["b"],
            "packets": p["packets"],
            "bytes": p["bytes"],
            "forwarded_packets": p["forwarded_packets"],
            "via": sorted(p["via"]),
            "directions": sorted(p["directions"]),
            "direct_link": p["direct_link"],
            "first_seen": _fmt_dt(p["first_seen"]),
            "last_seen": _fmt_dt(p["last_seen"]),
        }

    return {
        "meta": {
            "stats": stats or {},
            "first_seen": _fmt_dt(analysis.first_seen),
            "last_seen": _fmt_dt(analysis.last_seen),
            "events_without_local": analysis.events_without_local,
        },
        "nodes": [node_dict(n) for n in analysis.sorted_nodes()],
        "flows": [flow_dict(f) for f in analysis.sorted_flows()],
        "communication_pairs": [pair_dict(p) for p in analysis.communication_pairs()],
        "policies": policies(analysis),
        "relays": {relay: {f"{s}->{d}": c for (s, d), c in counter.items()}
                   for relay, counter in analysis.relays.items()},
        "subnets": analysis.subnets,
        "direct_links": [sorted(list(pair)) for pair in analysis.direct_links],
    }


def render_json(analysis: Analysis, stats: Optional[dict] = None) -> str:
    return json.dumps(to_dict(analysis, stats), indent=2, ensure_ascii=False)


def render_dot(analysis: Analysis) -> str:
    """Graphviz DOT: solid edges = direct flows, dashed = relayed."""
    out = ["digraph tinc_traffic {", '  rankdir=LR;',
           '  node [shape=box, style=rounded];']
    for n in analysis.sorted_nodes():
        label = n.name
        if n.subnets:
            label += "\\n" + ", ".join(sorted(n.subnets))
        style = "" if n.has_log else ", style=\"rounded,dashed\""
        out.append(f'  "{n.name}" [label="{label}"{style}];')
    for f in analysis.sorted_flows():
        if not (f.packets or f.forwarded_packets):
            continue
        label = f"{f.packets}p"
        if f.bytes:
            label += f"/{_fmt_bytes(f.bytes)}"
        style = ' style=dashed color="gray40"' if f.relayed else ""
        out.append(f'  "{f.src}" -> "{f.dst}" [label="{label}"{style}];')
    out.append("}")
    return "\n".join(out) + "\n"
