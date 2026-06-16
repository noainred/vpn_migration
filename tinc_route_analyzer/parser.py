"""Parsing of tinc VPN log lines.

A tinc log line is (optionally) wrapped in a syslog-style prefix that differs
per operating system / collection method, followed by a stable tinc message
body:

    BSD syslog   :  ``Jun 16 10:20:01 hq tinc.office[1010]: <message>``
    ISO / journal:  ``2026-06-16T10:20:01+09:00 cloud tinc.office[3030]: <message>``
    macOS        :  ``Jun 16 10:20:07 laptop tincd[789]: <message>``
    Windows / -d :  ``<message>``   (bare console output, no prefix)

The :func:`parse_line` function first peels off whatever prefix is present
(recording the originating host and timestamp), then matches the message body
against a small registry of well-known tinc messages.  The message bodies are
stable across tinc versions and operating systems, which is what makes
cross-OS analysis possible.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator, Optional, Tuple

from .models import EventType, LogEvent

DEFAULT_YEAR = datetime.now().year

# --- prefix handling -------------------------------------------------------

_BSD_TS = r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
_ISO_TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?"

# "<timestamp>? <host>? <prog>[pid]: <message>" — the program token must start
# with "tinc" so we never mistake an arbitrary word for the syslog tag.
_PREFIX_RE = re.compile(
    rf"^(?:(?P<ts>{_ISO_TS}|{_BSD_TS})\s+)?"
    rf"(?:(?P<host>[\w.-]+)\s+)?"
    rf"(?P<prog>tinc[\w.@-]*)(?:\[(?P<pid>\d+)\])?:\s*"
    rf"(?P<msg>.*)$"
)

_BSD_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _parse_timestamp(ts: Optional[str], year: int) -> Optional[datetime]:
    """Parse a syslog/ISO timestamp into a *naive* (wall-clock) datetime.

    Timestamps across OSes mix naive (BSD syslog) and timezone-aware (ISO)
    forms.  To keep them comparable we drop the timezone and keep the
    wall-clock value exactly as written; normalise logs to one timezone (or
    UTC) beforehand if you need cross-host correlation across offsets.
    """
    if not ts:
        return None
    ts = ts.strip()
    # BSD: "Jun 16 10:20:01" (no year)
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", ts)
    if m:
        mon = _BSD_MONTHS.get(m.group(1))
        if not mon:
            return None
        return datetime(year, mon, int(m.group(2)),
                        int(m.group(3)), int(m.group(4)), int(m.group(5)))
    # ISO 8601 — normalise a trailing "Z" and a "+0900"/"+09:00" offset.
    iso = ts.replace("Z", "+00:00").replace(" ", "T", 1)
    m = re.match(r"^(.*[+-]\d{2})(\d{2})$", iso)
    if m:  # "+0900" -> "+09:00"
        iso = f"{m.group(1)}:{m.group(2)}"
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


def split_prefix(raw: str) -> Tuple[Optional[str], Optional[str], str]:
    """Return ``(timestamp_str, host, message)`` for a raw log line.

    If no syslog prefix is recognised the whole line is treated as the
    message and ``timestamp_str`` / ``host`` are ``None``.
    """
    m = _PREFIX_RE.match(raw.rstrip("\n"))
    if not m:
        return None, None, raw.strip()
    return m.group("ts"), m.group("host"), m.group("msg").strip()


# --- message body patterns -------------------------------------------------
#
# Each entry maps an EventType to a compiled regex.  Named groups are copied
# onto the resulting LogEvent.  Patterns are tried in order; the first match
# wins, so put more specific patterns first.  Adding support for a new tinc
# message is just a matter of appending a pattern here.

_ADDR = r"\((?P<addr>[^)]*)\)"  # "(203.0.113.10 port 655)"

_PATTERNS: list[Tuple[EventType, re.Pattern]] = [
    (EventType.PACKET_RECEIVED, re.compile(
        rf"Received packet of (?P<size>\d+) bytes from (?P<peer>\S+) {_ADDR}")),
    (EventType.PACKET_SENT, re.compile(
        rf"Sending packet of (?P<size>\d+) bytes to (?P<peer>\S+) {_ADDR}"
        rf"(?: via (?P<via>\S+) \([^)]*\))?")),
    (EventType.PACKET_FORWARDED, re.compile(
        rf"Forwarding packet from (?P<src>\S+) to (?P<dst>\S+) {_ADDR}")),
    (EventType.CONNECTION_ACTIVATED, re.compile(
        rf"Connection with (?P<peer>\S+) {_ADDR} activated")),
    (EventType.CONNECTION_CLOSED, re.compile(
        rf"(?:Closing connection with|Connection closed by|Closing connection from) "
        rf"(?P<peer>\S+) {_ADDR}")),
    # "Got ADD_SUBNET from <peer> (<addr>) for <owner> <subnet>" — the
    # "for <owner> <subnet>" tail is only present on verbose builds.
    (EventType.SUBNET_ADDED, re.compile(
        rf"Got ADD_SUBNET from (?P<peer>\S+) {_ADDR}"
        rf"(?: for (?P<owner>\S+) (?P<subnet>\S+))?")),
    # Raw on-wire form: "ADD_SUBNET <id> <owner> <subnet>"
    (EventType.SUBNET_ADDED, re.compile(
        r"\bADD_SUBNET\b\s+\S+\s+(?P<owner>\S+)\s+(?P<subnet>[0-9a-fA-F:.]+/\d+)")),
    (EventType.EDGE_ADDED, re.compile(
        rf"Got ADD_EDGE from (?P<peer>\S+) {_ADDR}"
        rf"(?: for (?P<src>\S+) to (?P<dst>\S+))?")),
    (EventType.MAC_LEARNED, re.compile(
        rf"Learned new MAC address (?P<mac>[0-9a-fA-F:]+) from (?P<peer>\S+) {_ADDR}")),
    (EventType.ROUTE_ERROR, re.compile(
        rf"Cannot route packet from (?P<peer>\S+) {_ADDR}: (?P<reason>.*)")),
]


def _build_event(etype: EventType, gd: dict, raw: str) -> LogEvent:
    """Turn a regex match's group dict into a LogEvent."""
    size = gd.get("size")
    ev = LogEvent(
        raw=raw,
        event_type=etype,
        peer_node=gd.get("peer"),
        peer_address=(gd.get("addr") or None),
        src_node=gd.get("src"),
        dst_node=gd.get("dst"),
        via_node=gd.get("via"),
        owner_node=gd.get("owner"),
        subnet=gd.get("subnet"),
        mac=gd.get("mac"),
        size=int(size) if size is not None else None,
        reason=gd.get("reason"),
    )
    return ev


def parse_line(
    raw: str,
    *,
    default_node: Optional[str] = None,
    host_map: Optional[dict] = None,
    year: int = DEFAULT_YEAR,
    source_file: Optional[str] = None,
    line_no: Optional[int] = None,
) -> Optional[LogEvent]:
    """Parse a single raw log line into a :class:`LogEvent`.

    ``default_node`` is used as the observing node when the line carries no
    syslog hostname (e.g. bare Windows console output).  ``host_map`` lets you
    translate an OS hostname into the tinc node name when they differ.
    Returns ``None`` for lines that contain no tinc message we recognise.
    """
    if not raw or not raw.strip():
        return None

    ts_str, host, msg = split_prefix(raw)

    matched: Optional[LogEvent] = None
    for etype, pattern in _PATTERNS:
        m = pattern.search(msg)
        if m:
            matched = _build_event(etype, m.groupdict(), raw.rstrip("\n"))
            break
    if matched is None:
        return None

    # Resolve the observing ("local") node: prefer the per-line syslog host
    # (handles a central log server collecting from every machine), then fall
    # back to the per-file default.
    if host and host_map:
        host = host_map.get(host, host)
    matched.local_node = host or default_node
    matched.timestamp = _parse_timestamp(ts_str, year)
    matched.source_file = source_file
    matched.line_no = line_no
    return matched


def iter_events(
    lines: Iterable[str],
    *,
    default_node: Optional[str] = None,
    host_map: Optional[dict] = None,
    year: int = DEFAULT_YEAR,
    source_file: Optional[str] = None,
) -> Iterator[Tuple[int, LogEvent]]:
    """Yield ``(line_no, LogEvent)`` for every recognised line in ``lines``."""
    for i, raw in enumerate(lines, start=1):
        ev = parse_line(
            raw,
            default_node=default_node,
            host_map=host_map,
            year=year,
            source_file=source_file,
            line_no=i,
        )
        if ev is not None:
            yield i, ev
