"""Analysis of tshark / Wireshark packet-capture CSV exports.

This complements the tinc-log analyzer with a second, richer input: a CSV
produced by ``tshark -T fields`` such as::

    tshark -i ens192 -T fields -E header=y -E separator=, \
        -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
        -e ip.proto -e frame.len > network.csv

Every row is one captured packet.  We aggregate the packets into:

* **conversations** — *deduplicated* host pairs (A->B and B->A are the same
  conversation), with per-direction byte/packet counts;
* **services** — the listening (server) port per flow, e.g. ``TCP/665`` — the
  basis for NSX firewall rules;
* **hosts** — inventory with subnet, role (server/client/both) and volume;
* **subnet matrix** — subnet-to-subnet traffic for group-level NSX policy.

The column order is taken from a header row when present (``-E header=y``);
otherwise the default tshark order above is assumed.
"""

from __future__ import annotations

import csv
import gzip
import io
import itertools
import json
import os
import re
from datetime import datetime
from functools import lru_cache
from typing import Callable, Iterable, Iterator, Optional, Tuple

from .reporter import _fmt_bytes, _fmt_dt, _table

# --- constants -------------------------------------------------------------

PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 132: "SCTP",
}

# tshark field name -> our internal key
_FIELD_ALIASES = {
    "frame.time": "time", "frame.time_utc": "time", "frame.time_epoch": "epoch",
    "ip.src": "src", "ipv6.src": "src", "ip.dst": "dst", "ipv6.dst": "dst",
    "tcp.srcport": "sport", "udp.srcport": "sport",
    "tcp.dstport": "dport", "udp.dstport": "dport",
    "ip.proto": "proto", "frame.len": "length", "frame.cap_len": "length",
    "tcp.flags": "flags", "tcp.flags.syn": "syn", "tcp.flags.ack": "ack",
}
_DEFAULT_ORDER = ["time", "src", "dst", "sport", "dport", "proto", "length"]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
_TIME_RE = re.compile(
    r"([A-Za-z]{3})\s+(\d{1,2}),?\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?")
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def proto_name(proto) -> str:
    try:
        return PROTO_NAMES.get(int(proto), str(proto))
    except (TypeError, ValueError):
        return str(proto)


def service_label(proto, port) -> str:
    if port is None:
        return proto_name(proto)
    return f"{proto_name(proto)}/{port}"


@lru_cache(maxsize=1_000_000)
def subnet_of(ip: str) -> str:
    """Return the /24 (IPv4) the address belongs to; the ip itself otherwise.

    Cached: the number of distinct IPs is bounded by network cardinality, so
    this stays cheap even over hundreds of millions of packets.
    """
    if ip:
        dot = ip.rfind(".")
        if dot > 0 and ip.count(".") == 3 and ":" not in ip:
            return ip[:dot] + ".0/24"
    return ip or "?"


def _to_int(val) -> Optional[int]:
    if not val:
        return None
    val = val.strip()
    if val.isdigit():            # fast path: a plain port/length/proto number
        return int(val)
    if not val:
        return None
    # tshark sometimes emits "443,8080" for layered frames — take the first.
    head = val.split(",", 1)[0].strip()
    return int(head) if head.isdigit() else None


def parse_time(val: str) -> Optional[datetime]:
    """Parse a tshark ``frame.time`` string into a naive datetime.

    Example input: ``"Jun 16, 2026 14:07:00.649943933 KST"``.  Nanosecond
    precision is truncated to microseconds and the timezone label is dropped
    (wall-clock comparison, consistent with the rest of the toolkit).
    """
    if not val:
        return None
    # Fast path for the stable tshark layout "Mon DD, YYYY HH:MM:SS.fff TZ".
    try:
        parts = val.split()
        mon = _MONTHS.get(parts[0])
        if mon is not None and len(parts) >= 4:
            hms = parts[3]
            micro = 0
            dot = hms.find(".")
            if dot != -1:
                micro = int(hms[dot + 1:dot + 7].ljust(6, "0"))
                hms = hms[:dot]
            h, m_, s = hms.split(":")
            return datetime(int(parts[2]), mon, int(parts[1].rstrip(",")),
                            int(h), int(m_), int(s), micro)
    except (ValueError, IndexError, KeyError):
        pass
    # Fallback: tolerant regex for non-standard layouts.
    m = _TIME_RE.search(val)
    if not m:
        return None
    mon = _MONTHS.get(m.group(1))
    if not mon:
        return None
    frac = (m.group(7) or "0")[:6].ljust(6, "0")
    try:
        return datetime(int(m.group(3)), mon, int(m.group(2)),
                        int(m.group(4)), int(m.group(5)), int(m.group(6)), int(frac))
    except ValueError:
        return None


# IANA RFC 6335 port ranges (documented fact, not a heuristic):
#   system/well-known 0-1023, user/registered 1024-49151, dynamic 49152-65535.
# OS ephemeral ranges in practice start lower: Linux default is 32768-60999
# (net.ipv4.ip_local_port_range), Windows 49152-65535. We use 32768 as the
# ephemeral floor so a Linux client port is recognised as the client side.
WELL_KNOWN_MAX = 1023
EPHEMERAL_MIN = 32768


def port_class(port) -> str:
    """IANA RFC 6335 classification of a port number."""
    if port is None:
        return "-"
    if port <= WELL_KNOWN_MAX:
        return "well-known"
    if port < 49152:
        return "registered"
    return "dynamic"


def _service_port(sport: Optional[int], dport: Optional[int], proto) -> Optional[int]:
    """Return the listening (server) port of a flow, or ``None`` if undetermined.

    Decided only from documented facts, never guessed:
      * an IANA system port (<=1023) is the server side when the peer port is
        higher;
      * a non-ephemeral port is the server side when the peer port is in the OS
        ephemeral range (>=32768).
    When both ports fall in the same class the initiator cannot be known from
    addressing alone (no TCP flags captured), so we return ``None`` and the
    flow is still counted at the conversation level without a service label.
    """
    try:
        p = int(proto)
    except (TypeError, ValueError):
        return None
    if p not in (6, 17, 132):  # TCP / UDP / SCTP
        return None
    if sport is None or dport is None:
        return None
    lo, hi = sorted((sport, dport))
    if lo <= WELL_KNOWN_MAX < hi:
        return lo
    if lo < EPHEMERAL_MIN <= hi:
        return lo
    return None


# --- parsing ---------------------------------------------------------------

class FlowRecord:
    __slots__ = ("time", "src", "dst", "sport", "dport", "proto", "length",
                 "syn", "ack")

    def __init__(self, time, src, dst, sport, dport, proto, length,
                 syn=None, ack=None):
        self.time = time
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.length = length
        self.syn = syn   # TCP SYN flag (True/False), or None if not captured
        self.ack = ack   # TCP ACK flag (True/False), or None if not captured


def _parse_flags(flags, syn, ack):
    """Return (syn, ack) booleans from tcp.flags hex or the boolean columns."""
    if syn is not None or ack is not None:
        truthy = ("1", "true", "True")
        return ((syn or "").strip() in truthy if syn is not None else None,
                (ack or "").strip() in truthy if ack is not None else None)
    if flags:
        try:
            val = int(flags, 16) if flags.strip().lower().startswith("0x") \
                else int(flags)
        except ValueError:
            return None, None
        return bool(val & 0x02), bool(val & 0x10)  # SYN=0x02, ACK=0x10
    return None, None


def _column_map(first_row: list) -> Optional[dict]:
    """If ``first_row`` is a tshark header, return {internal_key: index}.

    When a key has two source columns (e.g. tcp.srcport and udp.srcport both
    map to ``sport``), the second is recorded as ``<key>2`` so the parser can
    fall back to it for the other transport.
    """
    if not any("." in cell for cell in first_row):
        return None
    cmap = {}
    for i, cell in enumerate(first_row):
        key = _FIELD_ALIASES.get(cell.strip())
        if not key:
            continue
        if key not in cmap:
            cmap[key] = i
        elif key + "2" not in cmap:
            cmap[key + "2"] = i
    return cmap or None


def _emit(reader, cmap: dict, parse_times: bool) -> Iterator[FlowRecord]:
    """Turn already-split CSV rows into FlowRecords using a fixed column map."""
    i_time = cmap.get("time", -1)
    i_src = cmap.get("src", -1)
    i_dst = cmap.get("dst", -1)
    i_sport = cmap.get("sport", -1)
    i_dport = cmap.get("dport", -1)
    i_sport2 = cmap.get("sport2", -1)   # e.g. udp port when tcp is primary
    i_dport2 = cmap.get("dport2", -1)
    i_proto = cmap.get("proto", -1)
    i_len = cmap.get("length", -1)
    i_flags = cmap.get("flags", -1)
    i_syn = cmap.get("syn", -1)
    i_ack = cmap.get("ack", -1)
    have_flags = i_flags >= 0 or i_syn >= 0 or i_ack >= 0
    want_time = parse_times and i_time >= 0
    for row in reader:
        n = len(row)
        if not (0 <= i_src < n and 0 <= i_dst < n):
            continue
        src = row[i_src].strip()
        dst = row[i_dst].strip()
        if not src or not dst:
            continue
        proto = _to_int(row[i_proto]) if 0 <= i_proto < n else None
        sport = _to_int(row[i_sport]) if 0 <= i_sport < n else None
        if sport is None and 0 <= i_sport2 < n:
            sport = _to_int(row[i_sport2])
        dport = _to_int(row[i_dport]) if 0 <= i_dport < n else None
        if dport is None and 0 <= i_dport2 < n:
            dport = _to_int(row[i_dport2])
        syn = ack = None
        if have_flags:
            syn, ack = _parse_flags(
                row[i_flags] if 0 <= i_flags < n else None,
                row[i_syn] if 0 <= i_syn < n else None,
                row[i_ack] if 0 <= i_ack < n else None)
        yield FlowRecord(
            time=parse_time(row[i_time]) if want_time and i_time < n else None,
            src=src, dst=dst, sport=sport, dport=dport,
            proto=proto if proto is not None else 0,
            length=(_to_int(row[i_len]) or 0) if 0 <= i_len < n else 0,
            syn=syn, ack=ack,
        )


def iter_flow_records(lines: Iterable[str], parse_times: bool = True
                      ) -> Iterator[FlowRecord]:
    """Yield :class:`FlowRecord` for each parseable row of a tshark CSV.

    ``lines`` is any iterable of strings — a file object (streamed, so a
    tens-of-GB capture is processed without being loaded into memory), a list,
    or an ``io.StringIO``.
    """
    reader = csv.reader(lines)
    cmap = None
    pending = None
    for row in reader:
        if not row or not any(c.strip() for c in row):
            continue
        m = _column_map(row)
        if m is not None:
            cmap = m            # header row consumed
        else:
            cmap = {k: i for i, k in enumerate(_DEFAULT_ORDER)}
            pending = row       # first row was data, not a header
        break
    if cmap is None:
        return
    rows = reader if pending is None else itertools.chain((pending,), reader)
    yield from _emit(rows, cmap, parse_times)


def detect_layout(path: str) -> Tuple[dict, bool]:
    """Return ``(column_map, has_header)`` from the first data-bearing line."""
    with _open_lines(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            row = next(csv.reader([line]), [])
            m = _column_map(row)
            if m is not None:
                return m, True
            return {k: i for i, k in enumerate(_DEFAULT_ORDER)}, False
    return {k: i for i, k in enumerate(_DEFAULT_ORDER)}, False


def looks_like_flow_csv(text: str) -> bool:
    """Heuristic: does this text look like a tshark/Wireshark CSV export?"""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "ip.src" in line or "ip.dst" in line or "frame.time" in line:
            return True
        row = next(csv.reader([line]), [])
        ip_cells = sum(1 for c in row if _IPV4_RE.match(c.strip()))
        return ip_cells >= 2
    return False


# --- aggregation -----------------------------------------------------------

def _min_dt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a < b else b


def _max_dt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if a > b else b


class FlowAnalysis:
    def __init__(self) -> None:
        self.hosts: dict = {}
        self.convs: dict = {}
        self.services: dict = {}
        self.subnet_matrix: dict = {}
        self.proto_stats: dict = {}
        self.packets = 0
        self.bytes = 0
        self.first: Optional[datetime] = None
        self.last: Optional[datetime] = None

    def _host(self, ip):
        h = self.hosts.get(ip)
        if h is None:
            h = {"ip": ip, "subnet": subnet_of(ip), "sent_bytes": 0,
                 "sent_packets": 0, "recv_bytes": 0, "recv_packets": 0,
                 "peers": set(), "offered": set(), "is_client": False,
                 "first": None, "last": None}
            self.hosts[ip] = h
        return h

    def _conv(self, a, b):
        key = tuple(sorted((a, b)))
        c = self.convs.get(key)
        if c is None:
            c = {"a": key[0], "b": key[1], "packets": 0, "bytes": 0,
                 "ab_packets": 0, "ab_bytes": 0, "ba_packets": 0, "ba_bytes": 0,
                 "services": set(), "protocols": set(), "ports": set(),
                 "first": None, "last": None}
            self.convs[key] = c
        return c

    def add_record(self, rec: FlowRecord) -> None:
        length = rec.length
        t = rec.time
        src = rec.src
        dst = rec.dst
        self.packets += 1
        self.bytes += length
        if t is not None:
            if self.first is None or t < self.first:
                self.first = t
            if self.last is None or t > self.last:
                self.last = t

        ps = self.proto_stats.get(rec.proto)
        if ps is None:
            self.proto_stats[rec.proto] = [1, length]
        else:
            ps[0] += 1
            ps[1] += length

        hs = self._host(src)
        hd = self._host(dst)
        hs["sent_bytes"] += length
        hs["sent_packets"] += 1
        hs["peers"].add(dst)
        hd["recv_bytes"] += length
        hd["recv_packets"] += 1
        hd["peers"].add(src)

        c = self._conv(src, dst)
        c["packets"] += 1
        c["bytes"] += length
        c["protocols"].add(rec.proto)
        if src == c["a"]:
            c["ab_packets"] += 1
            c["ab_bytes"] += length
        else:
            c["ba_packets"] += 1
            c["ba_bytes"] += length
        if t is not None:
            # Per-host and per-conversation first/last (only timestamps compared).
            if hs["first"] is None or t < hs["first"]:
                hs["first"] = t
            if hs["last"] is None or t > hs["last"]:
                hs["last"] = t
            if hd["first"] is None or t < hd["first"]:
                hd["first"] = t
            if hd["last"] is None or t > hd["last"]:
                hd["last"] = t
            if c["first"] is None or t < c["first"]:
                c["first"] = t
            if c["last"] is None or t > c["last"]:
                c["last"] = t

        # Determine the server (listening) side. A TCP handshake packet is
        # authoritative (fact); otherwise fall back to IANA port-range inference.
        sp = server = client = basis = None
        if rec.proto == 6 and rec.syn:
            if rec.ack:                       # SYN-ACK: source is the server
                server, client, sp = src, dst, rec.sport
            else:                             # SYN: destination is the server
                server, client, sp = dst, src, rec.dport
            basis = "handshake"
        if sp is None:
            sp = _service_port(rec.sport, rec.dport, rec.proto)
            if sp is not None:
                server, client = (src, dst) if rec.sport == sp else (dst, src)
                basis = "port-range"
        if sp is not None:
            c["services"].add((rec.proto, sp))
            if rec.dport is not None:
                c["ports"].add(rec.dport)
            self._host(server)["offered"].add((rec.proto, sp))
            self._host(client)["is_client"] = True
            sk = (server, rec.proto, sp)
            sv = self.services.get(sk)
            if sv is None:
                sv = {"server": server, "proto": rec.proto, "port": sp,
                      "clients": set(), "packets": 0, "bytes": 0, "basis": basis}
                self.services[sk] = sv
            elif basis == "handshake":
                sv["basis"] = "handshake"   # handshake outranks port-range
            sv["clients"].add(client)
            sv["packets"] += 1
            sv["bytes"] += length
        else:
            c["services"].add((rec.proto, None))

        sa, sb = subnet_of(rec.src), subnet_of(rec.dst)
        smk = tuple(sorted((sa, sb)))
        sm = self.subnet_matrix.get(smk)
        if sm is None:
            sm = {"a": smk[0], "b": smk[1], "packets": 0, "bytes": 0,
                  "services": set(), "host_pairs": set()}
            self.subnet_matrix[smk] = sm
        sm["packets"] += 1
        sm["bytes"] += length
        sm["host_pairs"].add(tuple(sorted((rec.src, rec.dst))))
        if sp is not None:
            sm["services"].add((rec.proto, sp))

    # -- derived views ------------------------------------------------------

    def duration_seconds(self) -> float:
        if self.first and self.last:
            return round((self.last - self.first).total_seconds(), 6)
        return 0.0

    def sorted_hosts(self) -> list:
        return sorted(self.hosts.values(),
                      key=lambda h: -(h["sent_bytes"] + h["recv_bytes"]))

    def sorted_convs(self) -> list:
        return sorted(self.convs.values(), key=lambda c: -c["bytes"])

    def sorted_services(self) -> list:
        return sorted(self.services.values(), key=lambda s: -s["bytes"])

    def host_role(self, h) -> str:
        offered, client = bool(h["offered"]), h["is_client"]
        if offered and client:
            return "both"
        if offered:
            return "server"
        if client:
            return "client"
        return "peer"

    def merge(self, other: "FlowAnalysis") -> "FlowAnalysis":
        """Fold another analysis into this one (exact; used to combine the
        partial results of parallel workers)."""
        self.packets += other.packets
        self.bytes += other.bytes
        self.first = _min_dt(self.first, other.first)
        self.last = _max_dt(self.last, other.last)
        for p, v in other.proto_stats.items():
            cur = self.proto_stats.get(p)
            if cur is None:
                self.proto_stats[p] = [v[0], v[1]]
            else:
                cur[0] += v[0]
                cur[1] += v[1]
        for ip, oh in other.hosts.items():
            h = self.hosts.get(ip)
            if h is None:
                self.hosts[ip] = oh
                continue
            h["sent_bytes"] += oh["sent_bytes"]
            h["sent_packets"] += oh["sent_packets"]
            h["recv_bytes"] += oh["recv_bytes"]
            h["recv_packets"] += oh["recv_packets"]
            h["peers"] |= oh["peers"]
            h["offered"] |= oh["offered"]
            h["is_client"] = h["is_client"] or oh["is_client"]
            h["first"] = _min_dt(h["first"], oh["first"])
            h["last"] = _max_dt(h["last"], oh["last"])
        for k, oc in other.convs.items():
            c = self.convs.get(k)
            if c is None:
                self.convs[k] = oc
                continue
            for fld in ("packets", "bytes", "ab_packets", "ab_bytes",
                        "ba_packets", "ba_bytes"):
                c[fld] += oc[fld]
            c["services"] |= oc["services"]
            c["protocols"] |= oc["protocols"]
            c["ports"] |= oc["ports"]
            c["first"] = _min_dt(c["first"], oc["first"])
            c["last"] = _max_dt(c["last"], oc["last"])
        for k, os_ in other.services.items():
            s = self.services.get(k)
            if s is None:
                self.services[k] = os_
                continue
            s["clients"] |= os_["clients"]
            s["packets"] += os_["packets"]
            s["bytes"] += os_["bytes"]
            if os_.get("basis") == "handshake":
                s["basis"] = "handshake"   # handshake outranks port-range
        for k, om in other.subnet_matrix.items():
            m = self.subnet_matrix.get(k)
            if m is None:
                self.subnet_matrix[k] = om
                continue
            m["packets"] += om["packets"]
            m["bytes"] += om["bytes"]
            m["services"] |= om["services"]
            m["host_pairs"] |= om["host_pairs"]
        return self


# --- entry points ----------------------------------------------------------

def analyze_flow_texts(items: Iterable[Tuple[str, Optional[str], str]]
                       ) -> Tuple[FlowAnalysis, dict]:
    """Analyse in-memory tshark-CSV texts (portal / small samples).

    ``items`` = ``(name, _node, text)``.  For very large captures use
    :func:`analyze_flow_files`, which streams from disk instead.
    """
    analysis = FlowAnalysis()
    stats = {"files": 0, "records": 0, "sources": []}
    for name, _node, text in items:
        before = analysis.packets
        for rec in iter_flow_records(io.StringIO(text or "")):
            analysis.add_record(rec)
        stats["files"] += 1
        stats["records"] += analysis.packets - before
        stats["sources"].append({"name": name,
                                 "records": analysis.packets - before})
    return analysis, stats


def _open_lines(path: str):
    """Open a plain or gzip-compressed CSV as a streaming text line source."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace", newline="")


def _build_units(path: str, workers: int, parse_times: bool, target_chunk: int):
    """Split a path into picklable work units with exact, non-overlapping
    line-boundary ranges (so parallel workers never drop or double-count)."""
    if path.endswith(".gz"):
        # gzip is not seekable by byte range; process the whole file as one unit.
        return [(path, 0, None, (), parse_times, True, False)]
    size = os.path.getsize(path)
    cmap, has_header = detect_layout(path)
    cmap_items = tuple(cmap.items())
    if workers <= 1 or size < target_chunk * 2:
        return [(path, 0, None, cmap_items, parse_times, True, has_header)]
    nchunks = max(1, min(workers * 4, size // target_chunk))
    step = size // nchunks
    units = []
    with open(path, "rb") as f:
        for k in range(nchunks):
            start = k * step
            end = size if k == nchunks - 1 else (k + 1) * step
            if k == 0:
                skip_first = has_header          # skip header line only
            else:
                f.seek(start - 1)                # exact boundary test
                skip_first = f.read(1) != b"\n"  # mid-line start -> skip partial
            units.append((path, start, end, cmap_items, parse_times, False, skip_first))
    return units


def _process_unit(unit):
    """Worker: analyse one file or one byte-range chunk. Returns a partial
    :class:`FlowAnalysis` (small — bounded by network cardinality)."""
    path, start, end, cmap_items, parse_times, whole, skip_first = unit
    analysis = FlowAnalysis()
    if whole:
        with _open_lines(path) as fh:
            for rec in iter_flow_records(fh, parse_times=parse_times):
                analysis.add_record(rec)
        return analysis
    cmap = dict(cmap_items)
    with open(path, "rb") as f:
        f.seek(start)
        if skip_first:
            f.readline()

        def gen():
            while end is None or f.tell() < end:
                line = f.readline()
                if not line:
                    break
                yield line.decode("utf-8", "replace")

        for rec in _emit(csv.reader(gen()), cmap, parse_times):
            analysis.add_record(rec)
    return analysis


def analyze_flow_files(
    paths: Iterable[str],
    *,
    workers: int = 1,
    parse_times: bool = True,
    progress: Optional[Callable[[int, str], None]] = None,
    progress_every: int = 2_000_000,
    target_chunk: int = 64 * 1024 * 1024,
) -> Tuple[FlowAnalysis, dict]:
    """Stream one or more capture CSVs from disk (``.csv`` or ``.gz``).

    Single pass, with memory bounded by the number of distinct hosts /
    conversations / services (not the packet count), so it scales to
    arbitrarily large captures.  With ``workers > 1`` the inputs are split into
    exact line-boundary chunks and analysed in parallel, then merged.
    """
    paths = list(paths)
    stats = {"files": 0, "records": 0, "sources": [], "unreadable": []}
    readable = []
    for path in paths:
        if os.path.exists(path):
            readable.append(path)
        else:
            stats["unreadable"].append((path, "not found"))

    if workers <= 1:
        analysis = FlowAnalysis()
        for path in readable:
            before = analysis.packets
            try:
                fh = _open_lines(path)
            except OSError as exc:
                stats["unreadable"].append((path, str(exc)))
                continue
            try:
                for rec in iter_flow_records(fh, parse_times=parse_times):
                    analysis.add_record(rec)
                    if progress and analysis.packets % progress_every == 0:
                        progress(analysis.packets, path)
            finally:
                fh.close()
            stats["files"] += 1
            stats["records"] += analysis.packets - before
            stats["sources"].append({"name": os.path.basename(path),
                                     "records": analysis.packets - before})
            if progress:
                progress(analysis.packets, path)
        return analysis, stats

    # Parallel: build units, process in a pool, merge exact partial results.
    import multiprocessing as mp

    units = []
    for path in readable:
        units.extend(_build_units(path, workers, parse_times, target_chunk))
    analysis = FlowAnalysis()
    per_path = {}
    with mp.Pool(processes=workers) as pool:
        for unit, partial in zip(units, pool.imap(_process_unit, units)):
            analysis.merge(partial)
            per_path[unit[0]] = per_path.get(unit[0], 0) + partial.packets
            if progress:
                progress(analysis.packets, unit[0])
    stats["files"] = len(readable)
    stats["records"] = analysis.packets
    stats["sources"] = [{"name": os.path.basename(p), "records": per_path.get(p, 0)}
                        for p in readable]
    return analysis, stats


# --- serialisation / reports -----------------------------------------------

def to_dict(analysis: FlowAnalysis, stats: Optional[dict] = None) -> dict:
    def svc_list(pairs):
        return [{"proto": proto_name(p), "port": port,
                 "label": service_label(p, port)} for (p, port) in sorted(
                     pairs, key=lambda x: (x[1] is None, x[1] or 0))]

    hosts = []
    for h in analysis.sorted_hosts():
        hosts.append({
            "ip": h["ip"], "subnet": h["subnet"], "role": analysis.host_role(h),
            "services_offered": svc_list(h["offered"]),
            "peers": sorted(h["peers"]), "peer_count": len(h["peers"]),
            "sent_bytes": h["sent_bytes"], "sent_packets": h["sent_packets"],
            "recv_bytes": h["recv_bytes"], "recv_packets": h["recv_packets"],
            "total_bytes": h["sent_bytes"] + h["recv_bytes"],
            "first_seen": _fmt_dt(h["first"]), "last_seen": _fmt_dt(h["last"]),
        })

    conversations = []
    for c in analysis.sorted_convs():
        conversations.append({
            "a": c["a"], "b": c["b"], "packets": c["packets"], "bytes": c["bytes"],
            "a_to_b_packets": c["ab_packets"], "a_to_b_bytes": c["ab_bytes"],
            "b_to_a_packets": c["ba_packets"], "b_to_a_bytes": c["ba_bytes"],
            "services": svc_list(c["services"]),
            "protocols": [proto_name(p) for p in sorted(c["protocols"])],
            "first_seen": _fmt_dt(c["first"]), "last_seen": _fmt_dt(c["last"]),
            "duration_seconds": round((c["last"] - c["first"]).total_seconds(), 6)
            if c["first"] and c["last"] else 0.0,
        })

    services = []
    for s in analysis.sorted_services():
        clients = sorted(s["clients"])
        basis = s.get("basis", "port-range")
        if basis == "handshake":
            evidence = (f"TCP 3-way handshake observed (SYN); "
                        f"{len(clients)} distinct client host(s)")
        else:
            evidence = (f"IANA RFC 6335 port-range inference; {len(clients)} "
                        f"distinct client host(s) to {s['server']}:{s['port']}")
        services.append({
            "name": f"allow-{proto_name(s['proto'])}-{s['port']}-to-{s['server']}",
            "server": s["server"], "proto": proto_name(s["proto"]),
            "port": s["port"], "service": service_label(s["proto"], s["port"]),
            "port_class": port_class(s["port"]), "basis": basis,
            "clients": clients, "client_count": len(clients),
            "source_subnets": sorted({subnet_of(c) for c in clients}),
            "action": "ALLOW", "packets": s["packets"], "bytes": s["bytes"],
            "evidence": evidence,
        })

    subnet_matrix = []
    for sm in sorted(analysis.subnet_matrix.values(), key=lambda x: -x["bytes"]):
        subnet_matrix.append({
            "a": sm["a"], "b": sm["b"], "packets": sm["packets"],
            "bytes": sm["bytes"], "host_pairs": len(sm["host_pairs"]),
            "services": svc_list(sm["services"]),
        })

    protocols = [{"proto": proto_name(p), "packets": v[0], "bytes": v[1]}
                 for p, v in sorted(analysis.proto_stats.items(),
                                    key=lambda kv: -kv[1][1])]

    return {
        "mode": "flow",
        "meta": {
            "stats": stats or {},
            "packets": analysis.packets, "bytes": analysis.bytes,
            "hosts": len(analysis.hosts), "conversations": len(analysis.convs),
            "services": len(analysis.services),
            "first_seen": _fmt_dt(analysis.first), "last_seen": _fmt_dt(analysis.last),
            "duration_seconds": analysis.duration_seconds(),
        },
        "hosts": hosts,
        "conversations": conversations,
        "services": services,
        "subnet_matrix": subnet_matrix,
        "protocols": protocols,
    }


def _as_dict(data, stats: Optional[dict] = None) -> dict:
    """Accept either a live FlowAnalysis or an already-aggregated dict."""
    return data if isinstance(data, dict) else to_dict(data, stats)


def render_summary(data, stats: Optional[dict] = None) -> str:
    d = _as_dict(data, stats)
    m = d["meta"]
    out = ["packet capture traffic analysis (tshark CSV)", "=" * 60,
           f"packets {m['packets']:,}  bytes {_fmt_bytes(m['bytes'])}  "
           f"hosts {m['hosts']}  conversations {m['conversations']}  "
           f"services {m['services']}",
           f"time span {m['first_seen']} .. {m['last_seen']} "
           f"({m['duration_seconds']}s)", ""]
    out.append("Conversations (A<->B deduplicated)")
    out.append(_table(
        ["pair", "packets", "bytes", "A->B", "B->A", "services"],
        [[f"{c['a']} <-> {c['b']}", str(c["packets"]), _fmt_bytes(c["bytes"]),
          f"{c['a_to_b_packets']}", f"{c['b_to_a_packets']}",
          ", ".join(s["label"] for s in c["services"]) or "-"]
         for c in d["conversations"]]).rstrip("\n"))
    out.append("")
    out.append("Services / proposed NSX allow-policies")
    out.append(_table(
        ["service", "server", "clients", "packets", "bytes"],
        [[s["service"], s["server"], str(s["client_count"]),
          str(s["packets"]), _fmt_bytes(s["bytes"])] for s in d["services"]]
        ).rstrip("\n"))
    return "\n".join(out) + "\n"


def render_conversations_csv(data) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["node_a", "node_b", "total_packets", "total_bytes",
                "a_to_b_packets", "a_to_b_bytes", "b_to_a_packets",
                "b_to_a_bytes", "services", "protocols", "first_seen",
                "last_seen", "duration_seconds"])
    for c in _as_dict(data)["conversations"]:
        w.writerow([c["a"], c["b"], c["packets"], c["bytes"],
                    c["a_to_b_packets"], c["a_to_b_bytes"], c["b_to_a_packets"],
                    c["b_to_a_bytes"],
                    "|".join(s["label"] for s in c["services"]),
                    "|".join(c["protocols"]), c["first_seen"], c["last_seen"],
                    c["duration_seconds"]])
    return buf.getvalue()


def render_policies_csv(data) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["policy", "action", "source", "source_subnets", "destination",
                "service", "proto", "port", "basis", "client_count", "packets",
                "bytes"])
    for s in _as_dict(data)["services"]:
        w.writerow([s["name"], s["action"], "|".join(s["clients"]),
                    "|".join(s["source_subnets"]), s["server"], s["service"],
                    s["proto"], s["port"], s.get("basis", "port-range"),
                    s["client_count"], s["packets"], s["bytes"]])
    return buf.getvalue()


def render_hosts_csv(data) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "subnet", "role", "services_offered", "peers",
                "sent_bytes", "recv_bytes", "total_bytes", "packets"])
    for h in _as_dict(data)["hosts"]:
        w.writerow([h["ip"], h["subnet"], h["role"],
                    "|".join(s["label"] for s in h["services_offered"]),
                    h["peer_count"], h["sent_bytes"], h["recv_bytes"],
                    h["total_bytes"], h["sent_packets"] + h["recv_packets"]])
    return buf.getvalue()


def render_dot(data) -> str:
    d = _as_dict(data)
    out = ["digraph flow_traffic {", "  rankdir=LR;",
           '  node [shape=box, style=rounded, fontsize=10];']
    for h in d["hosts"]:
        svc = ", ".join(s["label"] for s in h["services_offered"])
        label = h["ip"] + (f"\\n{svc}" if svc else "")
        server = "  fillcolor=\"#eef0fe\" style=\"rounded,filled\"" \
            if h["services_offered"] else ""
        out.append(f'  "{h["ip"]}" [label="{label}"{server}];')
    maxb = max((c["bytes"] for c in d["conversations"]), default=1) or 1
    for c in d["conversations"]:
        w = 1 + 4 * (c["bytes"] / maxb)
        label = ", ".join(s["label"] for s in c["services"]) or _fmt_bytes(c["bytes"])
        out.append(f'  "{c["a"]}" -> "{c["b"]}" '
                   f'[dir=both penwidth={w:.2f} label="{label}" fontsize=9];')
    out.append("}")
    return "\n".join(out) + "\n"


def render_hosts(data) -> str:
    d = _as_dict(data)
    rows = [[h["ip"], h["subnet"], h["role"],
             ", ".join(s["label"] for s in h["services_offered"]) or "-",
             str(h["peer_count"]), _fmt_bytes(h["sent_bytes"]),
             _fmt_bytes(h["recv_bytes"])] for h in d["hosts"]]
    return "Hosts\n" + _table(
        ["ip", "subnet", "role", "services offered", "peers", "tx", "rx"], rows)


def render_services(data) -> str:
    d = _as_dict(data)
    rows = []
    for s in d["services"]:
        clients = ", ".join(s["clients"][:6]) + ("…" if len(s["clients"]) > 6 else "")
        rows.append([s["service"], s["server"], s.get("basis", "port-range"),
                     str(s["client_count"]), clients or "-", _fmt_bytes(s["bytes"])])
    return ("Services / proposed NSX allow-policies "
            "(server port: TCP handshake when seen, else IANA RFC 6335 ranges)\n"
            + _table(["service", "server", "basis", "#clients", "clients", "bytes"],
                     rows))


def render_subnets(data) -> str:
    d = _as_dict(data)
    rows = [[f'{m["a"]} <-> {m["b"]}', str(m["packets"]), _fmt_bytes(m["bytes"]),
             str(m["host_pairs"]),
             ", ".join(s["label"] for s in m["services"]) or "-"]
            for m in d["subnet_matrix"]]
    return "Subnet-to-subnet matrix (group-level NSX policy)\n" + _table(
        ["subnet pair", "packets", "bytes", "host pairs", "services"], rows)


def render_live(data, elapsed: float, pps: float, top: int = 15) -> str:
    """A refreshing terminal dashboard for live capture (clears the screen)."""
    d = _as_dict(data)
    m = d["meta"]
    out = ["\033[2J\033[H",  # clear screen + cursor home
           f"=== live flow monitor ===   elapsed {elapsed:.0f}s   {pps:,.0f} pkt/s",
           f"packets {m['packets']:,}  bytes {_fmt_bytes(m['bytes'])}  "
           f"hosts {m['hosts']}  conversations {m['conversations']}  "
           f"services {m['services']}", ""]
    out.append(f"Top conversations (A<->B deduplicated)")
    out.append(_table(["pair", "packets", "bytes", "services"],
        [[f"{c['a']} <-> {c['b']}", f"{c['packets']:,}", _fmt_bytes(c["bytes"]),
          ", ".join(s["label"] for s in c["services"]) or "-"]
         for c in d["conversations"][:top]]).rstrip("\n"))
    out.append("")
    out.append("Top services (proposed NSX allow-policies)")
    out.append(_table(["service", "server", "#clients", "packets", "bytes"],
        [[s["service"], s["server"], str(s["client_count"]),
          f"{s['packets']:,}", _fmt_bytes(s["bytes"])]
         for s in d["services"][:top]]).rstrip("\n"))
    out.append("\n(Ctrl+C to stop)")
    return "\n".join(out) + "\n"


def run_live(lines: Iterable[str], *, interval: float = 2.0, top: int = 15,
             parse_times: bool = True, out=None) -> "FlowAnalysis":
    """Consume a live line stream, refreshing the dashboard every ``interval``."""
    import sys
    import time
    out = out or sys.stdout
    analysis = FlowAnalysis()
    start = time.time()
    last_t, last_p = start, 0
    try:
        for rec in iter_flow_records(lines, parse_times=parse_times):
            analysis.add_record(rec)
            now = time.time()
            if now - last_t >= interval:
                pps = (analysis.packets - last_p) / (now - last_t)
                out.write(render_live(analysis, now - start, pps, top))
                out.flush()
                last_t, last_p = now, analysis.packets
    except KeyboardInterrupt:
        pass
    now = time.time()
    pps = (analysis.packets - last_p) / max(1e-9, now - last_t)
    out.write(render_live(analysis, now - start, pps, top))
    out.flush()
    return analysis


def main(argv=None) -> int:
    import argparse
    import glob
    import sys

    p = argparse.ArgumentParser(
        prog="tinc-flow-analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Stream tshark/Wireshark CSV captures (.csv or .gz, scales to "
            "tens of GB) and produce VPN-migration views: deduplicated "
            "conversations (A<->B), services, hosts, subnet matrix and "
            "proposed NSX allow-policies."),
        epilog=(
            "examples:\n"
            "  tinc-flow-analyzer network.csv\n"
            "  tinc-flow-analyzer --progress -f json -o report.json '/caps/*.csv.gz'\n"
            "  tinc-flow-analyzer -f policies-csv network.csv > policies.csv\n"
            "  tshark -i tun0 -l -T fields -E header=y -E separator=, \\\n"
            "      -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \\\n"
            "      -e udp.srcport -e udp.dstport -e ip.proto -e frame.len \\\n"
            "    | tinc-flow-analyzer --stdin --live\n\n"
            "Upload the resulting report.json to the web portal to visualise it."))
    p.add_argument("inputs", nargs="*", metavar="CSV",
                   help="capture CSV file(s); globs and .gz are supported "
                        "(omit when using --stdin)")
    p.add_argument("-f", "--format", default="summary", choices=[
        "summary", "hosts", "services", "subnets", "json",
        "conversations-csv", "policies-csv", "hosts-csv", "dot"])
    p.add_argument("-o", "--output", metavar="FILE")
    p.add_argument("-j", "--workers", type=int, default=1, metavar="N",
                   help="parallel workers; splits inputs into exact chunks "
                        "(default: 1)")
    p.add_argument("--stdin", action="store_true",
                   help="read the capture CSV from standard input (pipe from tshark)")
    p.add_argument("--live", action="store_true",
                   help="live dashboard: refresh the view every --interval seconds")
    p.add_argument("--interval", type=float, default=2.0, metavar="SEC",
                   help="live refresh interval in seconds (default: 2)")
    p.add_argument("--top", type=int, default=15, metavar="N",
                   help="rows shown in the live dashboard (default: 15)")
    p.add_argument("--no-time", action="store_true",
                   help="skip per-packet timestamp parsing for max throughput "
                        "(drops the time-span/duration columns)")
    p.add_argument("--progress", action="store_true",
                   help="print packet-processing progress to stderr")
    args = p.parse_args(argv)

    use_stdin = args.stdin or args.inputs == ["-"]
    if not args.inputs and not use_stdin:
        p.error("no input given (provide CSV file(s) or --stdin)")

    paths = []
    if not use_stdin:
        for pat in args.inputs:
            matched = sorted(glob.glob(pat))
            paths.extend(matched or [pat])

    # Live dashboard mode (typically piped from `tshark -l`).
    if args.live:
        src = sys.stdin if use_stdin else itertools.chain.from_iterable(
            _open_lines(pp) for pp in paths)
        run_live(src, interval=args.interval, top=args.top,
                 parse_times=not args.no_time)
        return 0

    def prog(n, path):
        print(f"\r[flow] {n:,} packets processed ({os.path.basename(path)})",
              end="", file=sys.stderr, flush=True)

    if use_stdin:
        analysis = FlowAnalysis()
        for rec in iter_flow_records(sys.stdin, parse_times=not args.no_time):
            analysis.add_record(rec)
        stats = {"files": 1, "records": analysis.packets,
                 "sources": [{"name": "<stdin>", "records": analysis.packets}]}
    else:
        analysis, stats = analyze_flow_files(
            paths, workers=max(1, args.workers), parse_times=not args.no_time,
            progress=prog if args.progress else None)
        if args.progress:
            print("", file=sys.stderr)

    fmt = args.format
    if fmt == "summary":
        text = render_summary(analysis, stats)
    elif fmt == "hosts":
        text = render_hosts(analysis)
    elif fmt == "services":
        text = render_services(analysis)
    elif fmt == "subnets":
        text = render_subnets(analysis)
    elif fmt == "json":
        text = json.dumps(to_dict(analysis, stats), ensure_ascii=False, indent=2)
    elif fmt == "conversations-csv":
        text = render_conversations_csv(analysis)
    elif fmt == "policies-csv":
        text = render_policies_csv(analysis)
    elif fmt == "hosts-csv":
        text = render_hosts_csv(analysis)
    elif fmt == "dot":
        text = render_dot(analysis)
    else:  # pragma: no cover
        raise SystemExit(f"unknown format {fmt}")

    if not text.endswith("\n"):
        text += "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {fmt} to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    for pth, err in stats.get("unreadable", []):
        print(f"warning: could not read {pth}: {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
