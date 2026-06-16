"""Data models used across the analyzer.

The models are intentionally plain dataclasses so they serialise cleanly to
JSON and are easy to assert against in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    """The kinds of tinc log lines we extract meaning from."""

    PACKET_SENT = "packet_sent"            # local node -> peer (observed at the sender)
    PACKET_RECEIVED = "packet_received"    # peer -> local node (observed at the receiver)
    PACKET_FORWARDED = "packet_forwarded"  # src -> dst, relayed *through* the local node
    CONNECTION_ACTIVATED = "connection_activated"  # a direct meta/tunnel link came up
    CONNECTION_CLOSED = "connection_closed"
    SUBNET_ADDED = "subnet_added"          # a node announced ownership of a subnet
    EDGE_ADDED = "edge_added"              # topology edge announced
    MAC_LEARNED = "mac_learned"            # switch-mode MAC -> node mapping
    ROUTE_ERROR = "route_error"            # tinc could not route a packet
    OTHER = "other"                        # recognised tinc line we don't model


def _pick_ip(address: Optional[str]) -> Optional[str]:
    """Return just the IP from a tinc ``"<ip> port <n>"`` address string."""
    if not address:
        return None
    return address.split(" ", 1)[0].strip() or None


@dataclass
class LogEvent:
    """A single meaningful line extracted from a tinc log file."""

    raw: str
    event_type: EventType
    # ``local_node`` is the node whose log produced this line (the observer).
    local_node: Optional[str] = None
    src_node: Optional[str] = None
    dst_node: Optional[str] = None
    peer_node: Optional[str] = None      # the peer named in the message
    peer_address: Optional[str] = None   # real/physical address, e.g. "203.0.113.10 port 655"
    via_node: Optional[str] = None       # explicit relay named on a "... via X" line
    owner_node: Optional[str] = None     # subnet owner (ADD_SUBNET)
    subnet: Optional[str] = None
    mac: Optional[str] = None
    size: Optional[int] = None           # packet size in bytes, when present
    reason: Optional[str] = None         # route-error reason text
    timestamp: Optional[datetime] = None
    source_file: Optional[str] = None
    line_no: Optional[int] = None

    @property
    def peer_ip(self) -> Optional[str]:
        return _pick_ip(self.peer_address)


@dataclass
class FlowStats:
    """Aggregated directed traffic for a single (src -> dst) ordered pair.

    A real packet is logged twice: once at the sender ("Sending ... to dst")
    and once at the receiver ("Received ... from src").  To avoid double
    counting we keep the two observation sides separate and expose
    ``packets`` / ``bytes`` as the best single-count estimate (the larger of
    the two sides).  Forwarded packets are the *same* packets relayed through
    an intermediate node, so they are tracked separately as routing evidence
    and never added to the volume.
    """

    src: str
    dst: str
    sent_packets: int = 0      # observed at the source ("Sending ...")
    sent_bytes: int = 0
    recv_packets: int = 0      # observed at the destination ("Received ...")
    recv_bytes: int = 0
    forwarded_packets: int = 0  # observed at relays ("Forwarding ...")
    via: set[str] = field(default_factory=set)  # relay nodes seen carrying this flow
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    @property
    def packets(self) -> int:
        """Best single-count estimate of packets that travelled src -> dst."""
        return max(self.sent_packets, self.recv_packets, self.forwarded_packets)

    @property
    def bytes(self) -> int:
        """Best single-count estimate of bytes (forwarding lines carry no size)."""
        return max(self.sent_bytes, self.recv_bytes)

    @property
    def relayed(self) -> bool:
        return bool(self.via) or self.forwarded_packets > 0


@dataclass
class NodeInfo:
    """Everything we learned about a single tinc node."""

    name: str
    has_log: bool = False                # did we parse a log file written by this node?
    real_addresses: set[str] = field(default_factory=set)  # physical IP(s) = tunnel endpoints
    subnets: set[str] = field(default_factory=set)         # VPN subnets it owns
    peers: set[str] = field(default_factory=set)           # nodes it exchanged data with
    direct_links: set[str] = field(default_factory=set)    # nodes it had a direct tunnel to
    relays_used: set[str] = field(default_factory=set)     # relays it sent traffic through
    relayed_for: set[str] = field(default_factory=set)     # "src->dst" pairs it relayed
    sent_packets: int = 0
    sent_bytes: int = 0
    recv_packets: int = 0
    recv_bytes: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
