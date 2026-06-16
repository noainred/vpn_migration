"""Unit tests for tinc_route_analyzer.parser."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinc_route_analyzer.models import EventType  # noqa: E402
from tinc_route_analyzer.parser import parse_line, split_prefix  # noqa: E402


class TestPrefixSplitting(unittest.TestCase):
    def test_bsd_syslog_prefix(self):
        ts, host, msg = split_prefix(
            "Jun 16 10:20:01 hq tinc.office[1010]: Connection with cloud (1.2.3.4 port 655) activated")
        self.assertEqual(ts, "Jun 16 10:20:01")
        self.assertEqual(host, "hq")
        self.assertTrue(msg.startswith("Connection with cloud"))

    def test_iso_prefix_with_offset(self):
        ts, host, msg = split_prefix(
            "2026-06-16T10:20:01+09:00 cloud tinc.office[3030]: Sending packet of 84 bytes to hq (1.2.3.4 port 655)")
        self.assertEqual(ts, "2026-06-16T10:20:01+09:00")
        self.assertEqual(host, "cloud")
        self.assertIn("Sending packet", msg)

    def test_macos_tincd_prog(self):
        ts, host, msg = split_prefix(
            "Jun 16 10:20:07 laptop tincd[789]: Connection with cloud (1.2.3.4 port 655) activated")
        self.assertEqual(host, "laptop")
        self.assertIn("Connection with cloud", msg)

    def test_no_prefix_returns_whole_line(self):
        ts, host, msg = split_prefix("Sending packet of 84 bytes to hq (1.2.3.4 port 655)")
        self.assertIsNone(ts)
        self.assertIsNone(host)
        self.assertEqual(msg, "Sending packet of 84 bytes to hq (1.2.3.4 port 655)")


class TestMessageParsing(unittest.TestCase):
    def test_packet_sent(self):
        ev = parse_line(
            "Jun 16 10:21:10 hq tinc.office[1010]: Sending packet of 1200 bytes to branch1 (198.51.100.21 port 655)")
        self.assertEqual(ev.event_type, EventType.PACKET_SENT)
        self.assertEqual(ev.local_node, "hq")
        self.assertEqual(ev.peer_node, "branch1")
        self.assertEqual(ev.size, 1200)
        self.assertEqual(ev.peer_ip, "198.51.100.21")
        self.assertEqual(ev.timestamp.hour, 10)

    def test_packet_received(self):
        ev = parse_line(
            "2026-06-16T10:24:31+09:00 cloud tinc.office[3030]: Received packet of 640 bytes from branch1 (198.51.100.21 port 655)")
        self.assertEqual(ev.event_type, EventType.PACKET_RECEIVED)
        self.assertEqual(ev.local_node, "cloud")
        self.assertEqual(ev.peer_node, "branch1")
        self.assertEqual(ev.size, 640)

    def test_packet_forwarded(self):
        ev = parse_line(
            "2026-06-16T10:24:00+09:00 cloud tinc.office[3030]: Forwarding packet from laptop to branch2 (198.51.100.22 port 655)")
        self.assertEqual(ev.event_type, EventType.PACKET_FORWARDED)
        self.assertEqual(ev.local_node, "cloud")
        self.assertEqual(ev.src_node, "laptop")
        self.assertEqual(ev.dst_node, "branch2")

    def test_connection_activated(self):
        ev = parse_line(
            "Jun 16 10:20:01 hq tinc.office[1010]: Connection with cloud (203.0.113.10 port 655) activated")
        self.assertEqual(ev.event_type, EventType.CONNECTION_ACTIVATED)
        self.assertEqual(ev.peer_node, "cloud")
        self.assertEqual(ev.peer_ip, "203.0.113.10")

    def test_subnet_added_with_owner(self):
        ev = parse_line(
            "Jun 16 10:20:05 hq tinc.office[1010]: Got ADD_SUBNET from branch1 (198.51.100.21 port 655) for branch1 10.20.1.0/24")
        self.assertEqual(ev.event_type, EventType.SUBNET_ADDED)
        self.assertEqual(ev.owner_node, "branch1")
        self.assertEqual(ev.subnet, "10.20.1.0/24")

    def test_no_prefix_uses_default_node(self):
        ev = parse_line(
            "Sending packet of 150 bytes to laptop (192.0.2.50 port 655)",
            default_node="branch2")
        self.assertEqual(ev.event_type, EventType.PACKET_SENT)
        self.assertEqual(ev.local_node, "branch2")
        self.assertEqual(ev.peer_node, "laptop")

    def test_host_map_translates_hostname(self):
        ev = parse_line(
            "Jun 16 10:21:10 win-pc01 tinc.office[1010]: Sending packet of 84 bytes to hq (1.2.3.4 port 655)",
            host_map={"win-pc01": "branch2"})
        self.assertEqual(ev.local_node, "branch2")

    def test_sending_via_relay(self):
        ev = parse_line(
            "Jun 16 10:24:00 laptop tincd[789]: Sending packet of 300 bytes to branch2 (198.51.100.22 port 655) via cloud (203.0.113.10 port 655)")
        self.assertEqual(ev.event_type, EventType.PACKET_SENT)
        self.assertEqual(ev.peer_node, "branch2")
        self.assertEqual(ev.via_node, "cloud")

    def test_unrecognised_line_returns_none(self):
        self.assertIsNone(parse_line("Jun 16 10:20:01 hq tinc.office[1010]: Ready"))
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("some unrelated syslog line"))


if __name__ == "__main__":
    unittest.main()
