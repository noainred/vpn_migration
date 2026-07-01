"""Data models used across the analyzer.

Plain classes (no dataclasses) so the toolkit runs on Python 3.6+ and the
objects still serialise cleanly to JSON and are easy to assert against.
"""

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


def _pick_ip(address):
    """Return just the IP from a tinc ``"<ip> port <n>"`` address string."""
    if not address:
        return None
    return address.split(" ", 1)[0].strip() or None


class LogEvent(object):
    """A single meaningful line extracted from a tinc log file."""

    def __init__(self, raw, event_type, local_node=None, src_node=None,
                 dst_node=None, peer_node=None, peer_address=None, via_node=None,
                 owner_node=None, subnet=None, mac=None, size=None, reason=None,
                 timestamp=None, source_file=None, line_no=None):
        self.raw = raw
        self.event_type = event_type
        # ``local_node`` is the node whose log produced this line (the observer).
        self.local_node = local_node
        self.src_node = src_node
        self.dst_node = dst_node
        self.peer_node = peer_node          # the peer named in the message
        self.peer_address = peer_address    # real/physical address "203.0.113.10 port 655"
        self.via_node = via_node            # explicit relay named on a "... via X" line
        self.owner_node = owner_node        # subnet owner (ADD_SUBNET)
        self.subnet = subnet
        self.mac = mac
        self.size = size                    # packet size in bytes, when present
        self.reason = reason                # route-error reason text
        self.timestamp = timestamp
        self.source_file = source_file
        self.line_no = line_no

    @property
    def peer_ip(self):
        return _pick_ip(self.peer_address)


class FlowStats(object):
    """Aggregated directed traffic for a single (src -> dst) ordered pair.

    A real packet is logged twice: once at the sender ("Sending ... to dst")
    and once at the receiver ("Received ... from src").  To avoid double
    counting we keep the two observation sides separate and expose
    ``packets`` / ``bytes`` as the best single-count estimate (the larger of
    the two sides).  Forwarded packets are the *same* packets relayed through
    an intermediate node, so they are tracked separately as routing evidence
    and never added to the volume.
    """

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.sent_packets = 0      # observed at the source ("Sending ...")
        self.sent_bytes = 0
        self.recv_packets = 0      # observed at the destination ("Received ...")
        self.recv_bytes = 0
        self.forwarded_packets = 0  # observed at relays ("Forwarding ...")
        self.via = set()           # relay nodes seen carrying this flow
        self.first_seen = None      # type: Optional[object]
        self.last_seen = None

    @property
    def packets(self):
        """Best single-count estimate of packets that travelled src -> dst."""
        return max(self.sent_packets, self.recv_packets, self.forwarded_packets)

    @property
    def bytes(self):
        """Best single-count estimate of bytes (forwarding lines carry no size)."""
        return max(self.sent_bytes, self.recv_bytes)

    @property
    def relayed(self):
        return bool(self.via) or self.forwarded_packets > 0


class NodeInfo(object):
    """Everything we learned about a single tinc node."""

    def __init__(self, name, has_log=False):
        self.name = name
        self.has_log = has_log              # did we parse a log written by this node?
        self.real_addresses = set()         # physical IP(s) = tunnel endpoints
        self.subnets = set()                # VPN subnets it owns
        self.peers = set()                  # nodes it exchanged data with
        self.direct_links = set()           # nodes it had a direct tunnel to
        self.relays_used = set()            # relays it sent traffic through
        self.relayed_for = set()            # "src->dst" pairs it relayed
        self.sent_packets = 0
        self.sent_bytes = 0
        self.recv_packets = 0
        self.recv_bytes = 0
        self.first_seen = None
        self.last_seen = None
