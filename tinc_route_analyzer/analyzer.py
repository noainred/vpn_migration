"""Aggregation of parsed log events into a traffic / topology model."""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime
from typing import Iterable, Optional, Tuple

from .models import EventType, FlowStats, LogEvent, NodeInfo
from .parser import DEFAULT_YEAR, iter_events


def _min_dt(a: Optional[datetime], b: Optional[datetime]) -> Optional[datetime]:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _max_dt(a: Optional[datetime], b: Optional[datetime]) -> Optional[datetime]:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


class Analysis:
    """Accumulates :class:`LogEvent` objects into nodes, flows and routes."""

    def __init__(self) -> None:
        self.nodes: dict[str, NodeInfo] = {}
        self.flows: dict[Tuple[str, str], FlowStats] = {}
        # relay node -> Counter of (src, dst) pairs it forwarded
        self.relays: dict[str, Counter] = {}
        # subnet -> owning node
        self.subnets: dict[str, str] = {}
        # direct meta/tunnel links (unordered node pairs)
        self.direct_links: set[frozenset] = set()
        self.total_events = 0
        self.events_without_local = 0
        self.route_errors: list[LogEvent] = []
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None

    # -- helpers ------------------------------------------------------------

    def _node(self, name: Optional[str]) -> Optional[NodeInfo]:
        if not name:
            return None
        node = self.nodes.get(name)
        if node is None:
            node = NodeInfo(name=name)
            self.nodes[name] = node
        return node

    def _flow(self, src: str, dst: str) -> FlowStats:
        key = (src, dst)
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowStats(src=src, dst=dst)
            self.flows[key] = flow
        return flow

    def _touch_seen(self, ts: Optional[datetime], *objs) -> None:
        if ts is None:
            return
        self.first_seen = _min_dt(self.first_seen, ts)
        self.last_seen = _max_dt(self.last_seen, ts)
        for o in objs:
            if o is None:
                continue
            o.first_seen = _min_dt(o.first_seen, ts)
            o.last_seen = _max_dt(o.last_seen, ts)

    def _record_address(self, name: Optional[str], address: Optional[str]) -> None:
        node = self._node(name)
        if node is None or not address:
            return
        ip = address.split(" ", 1)[0].strip()
        if ip:
            node.real_addresses.add(ip)

    # -- main entry ---------------------------------------------------------

    def add_event(self, ev: LogEvent) -> None:
        self.total_events += 1
        ts = ev.timestamp
        local = self._node(ev.local_node)
        if local is not None:
            local.has_log = True

        et = ev.event_type

        if et == EventType.PACKET_SENT:
            self._record_address(ev.peer_node, ev.peer_address)
            if not ev.local_node or not ev.peer_node:
                self.events_without_local += 1
                return
            peer = self._node(ev.peer_node)
            flow = self._flow(ev.local_node, ev.peer_node)
            flow.sent_packets += 1
            flow.sent_bytes += ev.size or 0
            if ev.via_node:
                flow.via.add(ev.via_node)
                local.relays_used.add(ev.via_node)
            local.sent_packets += 1
            local.sent_bytes += ev.size or 0
            local.peers.add(ev.peer_node)
            peer.peers.add(ev.local_node)
            self._touch_seen(ts, flow, local, peer)

        elif et == EventType.PACKET_RECEIVED:
            self._record_address(ev.peer_node, ev.peer_address)
            if not ev.local_node or not ev.peer_node:
                self.events_without_local += 1
                return
            peer = self._node(ev.peer_node)
            flow = self._flow(ev.peer_node, ev.local_node)
            flow.recv_packets += 1
            flow.recv_bytes += ev.size or 0
            local.recv_packets += 1
            local.recv_bytes += ev.size or 0
            local.peers.add(ev.peer_node)
            peer.peers.add(ev.local_node)
            self._touch_seen(ts, flow, local, peer)

        elif et == EventType.PACKET_FORWARDED:
            # local node relays a packet whose endpoints are src and dst.
            self._record_address(ev.dst_node, ev.peer_address)
            if not ev.src_node or not ev.dst_node:
                return
            src = self._node(ev.src_node)
            dst = self._node(ev.dst_node)
            flow = self._flow(ev.src_node, ev.dst_node)
            flow.forwarded_packets += 1
            src.peers.add(ev.dst_node)
            dst.peers.add(ev.src_node)
            if ev.local_node:
                flow.via.add(ev.local_node)
                self.relays.setdefault(ev.local_node, Counter())[
                    (ev.src_node, ev.dst_node)] += 1
                local.relayed_for.add(f"{ev.src_node}->{ev.dst_node}")
                src.relays_used.add(ev.local_node)
            self._touch_seen(ts, flow, src, dst, local)

        elif et == EventType.CONNECTION_ACTIVATED:
            self._record_address(ev.peer_node, ev.peer_address)
            if ev.local_node and ev.peer_node:
                self.direct_links.add(frozenset((ev.local_node, ev.peer_node)))
                local.direct_links.add(ev.peer_node)
                self._node(ev.peer_node).direct_links.add(ev.local_node)
            self._touch_seen(ts, local, self._node(ev.peer_node))

        elif et == EventType.CONNECTION_CLOSED:
            self._record_address(ev.peer_node, ev.peer_address)
            self._touch_seen(ts, local, self._node(ev.peer_node))

        elif et == EventType.SUBNET_ADDED:
            self._record_address(ev.peer_node, ev.peer_address)
            if ev.owner_node and ev.subnet:
                self.subnets[ev.subnet] = ev.owner_node
                self._node(ev.owner_node).subnets.add(ev.subnet)
            self._touch_seen(ts, local, self._node(ev.peer_node),
                             self._node(ev.owner_node))

        elif et == EventType.EDGE_ADDED:
            self._record_address(ev.peer_node, ev.peer_address)
            if ev.src_node and ev.dst_node:
                self._node(ev.src_node)
                self._node(ev.dst_node)
            self._touch_seen(ts, local, self._node(ev.peer_node))

        elif et == EventType.MAC_LEARNED:
            self._record_address(ev.peer_node, ev.peer_address)
            self._touch_seen(ts, local, self._node(ev.peer_node))

        elif et == EventType.ROUTE_ERROR:
            self._record_address(ev.peer_node, ev.peer_address)
            self.route_errors.append(ev)
            self._touch_seen(ts, local, self._node(ev.peer_node))

    # -- derived views ------------------------------------------------------

    def communication_pairs(self) -> list[dict]:
        """Undirected node pairs that exchanged data, with merged volume.

        This is the key artefact for migration: each pair becomes one
        firewall / connectivity policy.
        """
        pairs: dict[frozenset, dict] = {}
        for (src, dst), flow in self.flows.items():
            key = frozenset((src, dst))
            agg = pairs.get(key)
            if agg is None:
                a, b = sorted((src, dst))
                agg = {
                    "a": a,
                    "b": b,
                    "packets": 0,
                    "bytes": 0,
                    "forwarded_packets": 0,
                    "via": set(),
                    "directions": set(),
                    "direct_link": frozenset((src, dst)) in self.direct_links,
                    "first_seen": None,
                    "last_seen": None,
                }
                pairs[key] = agg
            agg["packets"] += flow.packets
            agg["bytes"] += flow.bytes
            agg["forwarded_packets"] += flow.forwarded_packets
            agg["via"].update(flow.via)
            if flow.packets or flow.forwarded_packets:
                agg["directions"].add(f"{src}->{dst}")
            agg["first_seen"] = _min_dt(agg["first_seen"], flow.first_seen)
            agg["last_seen"] = _max_dt(agg["last_seen"], flow.last_seen)
        return sorted(pairs.values(), key=lambda p: (-p["bytes"], -p["packets"],
                                                     p["a"], p["b"]))

    def routed_flows(self) -> list[FlowStats]:
        """Flows that travelled through at least one relay node."""
        return sorted(
            (f for f in self.flows.values() if f.relayed),
            key=lambda f: (-f.packets, f.src, f.dst),
        )

    def sorted_flows(self) -> list[FlowStats]:
        return sorted(self.flows.values(),
                      key=lambda f: (-f.bytes, -f.packets, f.src, f.dst))

    def sorted_nodes(self) -> list[NodeInfo]:
        return sorted(self.nodes.values(), key=lambda n: n.name)


def analyze_files(
    file_specs: Iterable[Tuple[str, Optional[str]]],
    *,
    host_map: Optional[dict] = None,
    year: int = DEFAULT_YEAR,
    subnet_dumps: Optional[Iterable[str]] = None,
) -> Tuple[Analysis, dict]:
    """Parse and analyse a collection of log files.

    ``file_specs`` is an iterable of ``(path, node_name_or_None)``.  The node
    name is used as the observing node for lines without a syslog hostname.
    Returns ``(analysis, stats)`` where ``stats`` reports parse coverage.
    """
    analysis = Analysis()
    stats = {"files": 0, "lines": 0, "events": 0, "unparsed_files": []}

    for path, node in file_specs:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:  # pragma: no cover - surfaced to the caller
            stats["unparsed_files"].append((path, str(exc)))
            continue
        stats["files"] += 1
        stats["lines"] += len(lines)
        default_node = node or _node_from_filename(path)
        for _lineno, ev in iter_events(
            lines,
            default_node=default_node,
            host_map=host_map,
            year=year,
            source_file=os.path.basename(path),
        ):
            analysis.add_event(ev)
            stats["events"] += 1

    if subnet_dumps:
        for dump_path in subnet_dumps:
            _load_subnet_dump(analysis, dump_path)

    return analysis, stats


def _node_from_filename(path: str) -> Optional[str]:
    """Best-effort node name from a filename like ``linux_hq.log`` -> ``hq``."""
    stem = os.path.splitext(os.path.basename(path))[0]
    for prefix in ("linux_", "windows_", "macos_", "darwin_", "bsd_", "tinc_", "tincd_"):
        if stem.startswith(prefix):
            return stem[len(prefix):] or None
    return stem or None


def _load_subnet_dump(analysis: Analysis, path: str) -> None:
    """Load authoritative subnet ownership from ``tinc dump subnets`` output.

    Expected line format: ``<subnet> owner <node>`` (extra columns ignored).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                parts = raw.split()
                if len(parts) >= 3 and parts[1] == "owner":
                    subnet, owner = parts[0], parts[2]
                    analysis.subnets[subnet] = owner
                    analysis._node(owner).subnets.add(subnet)
    except OSError:
        pass
