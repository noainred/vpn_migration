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
]

__version__ = "1.0.0"
