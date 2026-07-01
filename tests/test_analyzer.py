"""Integration tests for the analyzer against the bundled sample logs."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinc_route_analyzer.analyzer import Analysis, analyze_files  # noqa: E402
from tinc_route_analyzer.models import EventType, LogEvent  # noqa: E402
from tinc_route_analyzer import reporter  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def _sample_specs():
    return [
        (os.path.join(SAMPLES, "linux_hq.log"), "hq"),
        (os.path.join(SAMPLES, "linux_cloud.log"), "cloud"),
        (os.path.join(SAMPLES, "windows_branch2.log"), "branch2"),
        (os.path.join(SAMPLES, "macos_laptop.log"), "laptop"),
    ]


class TestSampleAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analysis, cls.stats = analyze_files(_sample_specs(), year=2026)

    def test_all_nodes_discovered(self):
        self.assertEqual(set(self.analysis.nodes), {
            "hq", "cloud", "branch1", "branch2", "laptop"})

    def test_branch1_seen_only_via_peers(self):
        # branch1 has no log file of its own, but we still discover it.
        self.assertFalse(self.analysis.nodes["branch1"].has_log)
        self.assertTrue(self.analysis.nodes["hq"].has_log)

    def test_physical_addresses_captured(self):
        self.assertIn("198.51.100.21", self.analysis.nodes["branch1"].real_addresses)
        self.assertIn("203.0.113.1", self.analysis.nodes["hq"].real_addresses)

    def test_subnet_ownership(self):
        self.assertEqual(self.analysis.subnets["10.20.2.0/24"], "branch2")
        self.assertEqual(self.analysis.subnets["10.10.0.0/16"], "hq")
        self.assertEqual(len(self.analysis.subnets), 5)

    def test_directed_flow_volume(self):
        # hq -> branch1: two sent packets (84 + 1200), receiver has no log.
        flow = self.analysis.flows[("hq", "branch1")]
        self.assertEqual(flow.packets, 2)
        self.assertEqual(flow.bytes, 1284)

    def test_no_double_counting(self):
        # hq -> cloud is logged at both ends (sent at hq, received at cloud);
        # it must count as one packet of 1500 bytes, not two.
        flow = self.analysis.flows[("hq", "cloud")]
        self.assertEqual(flow.sent_packets, 1)
        self.assertEqual(flow.recv_packets, 1)
        self.assertEqual(flow.packets, 1)
        self.assertEqual(flow.bytes, 1500)

    def test_relayed_flow_detected(self):
        # laptop <-> branch2 has no direct tunnel; cloud relays it.
        flow = self.analysis.flows[("laptop", "branch2")]
        self.assertTrue(flow.relayed)
        self.assertIn("cloud", flow.via)
        self.assertEqual(flow.forwarded_packets, 2)
        self.assertIn(("laptop", "branch2"), self.analysis.relays["cloud"])

    def test_communication_pairs(self):
        pairs = {frozenset((p["a"], p["b"])): p
                 for p in self.analysis.communication_pairs()}
        lap_b2 = pairs[frozenset(("laptop", "branch2"))]
        self.assertIn("cloud", lap_b2["via"])
        self.assertFalse(lap_b2["direct_link"])  # no direct tunnel between them
        hq_cloud = pairs[frozenset(("hq", "cloud"))]
        self.assertTrue(hq_cloud["direct_link"])

    def test_routed_flows_view(self):
        routed = {(f.src, f.dst) for f in self.analysis.routed_flows()}
        self.assertIn(("laptop", "branch2"), routed)
        self.assertIn(("branch2", "laptop"), routed)

    def test_reports_render_without_error(self):
        for fn in (reporter.render_summary, reporter.render_nodes,
                   reporter.render_pairs, reporter.render_flows,
                   reporter.render_routes, reporter.render_subnets,
                   reporter.render_csv, reporter.render_json, reporter.render_dot):
            out = fn(self.analysis)
            self.assertIsInstance(out, str)
            self.assertTrue(out.strip())


class TestCentralSyslogPerLineHost(unittest.TestCase):
    """A single aggregated syslog file containing lines from several hosts."""

    def test_per_line_host_used_as_local_node(self):
        analysis = Analysis()
        from tinc_route_analyzer.parser import parse_line
        lines = [
            "Jun 16 10:21:10 hq tinc.office[1010]: Sending packet of 84 bytes to branch1 (198.51.100.21 port 655)",
            "Jun 16 10:21:11 cloud tinc.office[3030]: Sending packet of 90 bytes to hq (203.0.113.1 port 655)",
        ]
        for raw in lines:
            ev = parse_line(raw, default_node="ignored", year=2026)
            analysis.add_event(ev)
        self.assertIn(("hq", "branch1"), analysis.flows)
        self.assertIn(("cloud", "hq"), analysis.flows)


class TestEmptyAndMalformed(unittest.TestCase):
    def test_empty_analysis(self):
        analysis = Analysis()
        self.assertEqual(analysis.communication_pairs(), [])
        self.assertEqual(reporter.render_overview(analysis).count("nodes discovered : 0"), 1)

    def test_forwarded_without_local_still_records_endpoints(self):
        analysis = Analysis()
        ev = LogEvent(raw="x", event_type=EventType.PACKET_FORWARDED,
                      src_node="a", dst_node="b")
        analysis.add_event(ev)
        self.assertIn(("a", "b"), analysis.flows)


if __name__ == "__main__":
    unittest.main()
