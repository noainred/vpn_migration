"""Tests for the in-memory analysis path and the web portal backend."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinc_route_analyzer.analyzer import analyze_texts  # noqa: E402
from tinc_route_analyzer import reporter  # noqa: E402
from tinc_route_analyzer.web.server import analyze_payload, _read_samples  # noqa: E402


HQ_LOG = (
    "Jun 16 10:20:03 hq tinc.office[1010]: Connection with branch2 (198.51.100.22 port 655) activated\n"
    "Jun 16 10:20:05 hq tinc.office[1010]: Got ADD_SUBNET from branch2 (198.51.100.22 port 655) for branch2 10.20.2.0/24\n"
    "Jun 16 10:22:00 hq tinc.office[1010]: Sending packet of 540 bytes to branch2 (198.51.100.22 port 655)\n"
)
BR2_LOG = (  # no syslog prefix -> needs node mapping
    "Connection with hq (203.0.113.1 port 655) activated\n"
    "Received packet of 540 bytes from hq (203.0.113.1 port 655)\n"
    "Sending packet of 320 bytes to hq (203.0.113.1 port 655)\n"
)


class TestAnalyzeTexts(unittest.TestCase):
    def test_in_memory_matches_expectation(self):
        items = [("linux_hq.log", "hq", HQ_LOG), ("branch2.log", "branch2", BR2_LOG)]
        analysis, stats = analyze_texts(items, year=2026)
        self.assertEqual(set(analysis.nodes), {"hq", "branch2"})
        self.assertEqual(analysis.subnets["10.20.2.0/24"], "branch2")
        # hq -> branch2 logged at both ends (540 sent, 540 received) => 1 packet
        flow = analysis.flows[("hq", "branch2")]
        self.assertEqual(flow.packets, 1)
        self.assertEqual(flow.bytes, 540)

    def test_per_file_stats_recorded(self):
        items = [("linux_hq.log", "hq", HQ_LOG), ("branch2.log", "branch2", BR2_LOG)]
        _analysis, stats = analyze_texts(items, year=2026)
        self.assertEqual(stats["files"], 2)
        names = {s["name"]: s for s in stats["sources"]}
        self.assertEqual(names["branch2.log"]["node"], "branch2")
        self.assertTrue(names["branch2.log"]["events"] > 0)

    def test_subnet_dump_text(self):
        analysis, _ = analyze_texts(
            [("a.log", "a", "")],
            subnet_dump_texts=["10.30.0.0/24 owner cloud\n"], year=2026)
        self.assertEqual(analysis.subnets["10.30.0.0/24"], "cloud")


class TestPolicies(unittest.TestCase):
    def test_policy_carries_subnets_and_endpoints(self):
        items = [("linux_hq.log", "hq", HQ_LOG), ("branch2.log", "branch2", BR2_LOG)]
        analysis, _ = analyze_texts(items, year=2026)
        pols = reporter.policies(analysis)
        pol = next(p for p in pols if {p["a"], p["b"]} == {"hq", "branch2"})
        self.assertEqual(pol["action"], "ALLOW")
        self.assertIn("10.20.2.0/24", pol["b_subnets"] + pol["a_subnets"])
        csv = reporter.render_policies_csv(analysis)
        self.assertIn("policy,node_a,node_b", csv.splitlines()[0])


class TestWebBackend(unittest.TestCase):
    def test_analyze_payload_happy_path(self):
        payload = {
            "files": [
                {"name": "linux_hq.log", "node": "hq", "content": HQ_LOG},
                {"name": "branch2.log", "node": "branch2", "content": BR2_LOG},
            ],
            "year": 2026,
        }
        res = analyze_payload(payload)
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["data"]["nodes"]), 2)
        self.assertIn("policies", res["data"])
        self.assertIn("policies_csv", res["exports"])
        self.assertIn("dot", res["exports"])
        self.assertTrue(res["summaryText"].strip())

    def test_analyze_payload_no_files(self):
        res = analyze_payload({"files": []})
        self.assertFalse(res["ok"])
        self.assertIn("no files", res["error"])

    def test_node_defaults_from_filename_when_missing(self):
        payload = {"files": [{"name": "windows_branch2.log", "content": BR2_LOG}]}
        res = analyze_payload(payload)
        self.assertTrue(res["ok"])
        self.assertIn("branch2", res["data"]["nodes"][0]["name"])

    def test_read_samples_bundled(self):
        samples = _read_samples()
        self.assertTrue(samples)
        # first sample is the packet-capture CSV, then the tinc logs
        labels = [s["label"] for s in samples]
        self.assertIn("packet capture (tshark CSV)", labels)


FLOW_CSV = (
    "frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,ip.proto,frame.len\n"
    '"Jun 16, 2026 14:07:00.1 KST",10.94.40.36,10.93.168.39,665,41884,6,138\n'
    '"Jun 16, 2026 14:07:00.2 KST",10.93.168.39,10.94.40.36,41884,665,6,66\n'
)


class TestWebFlowMode(unittest.TestCase):
    def test_flow_csv_detected_and_analysed(self):
        res = analyze_payload({"files": [{"name": "network.csv", "content": FLOW_CSV}]})
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "flow")
        self.assertEqual(res["data"]["meta"]["hosts"], 2)
        # one deduplicated conversation, TCP/665 service detected factually
        self.assertEqual(res["data"]["meta"]["conversations"], 1)
        self.assertEqual(res["data"]["services"][0]["port"], 665)
        self.assertIn("conversations_csv", res["exports"])

    def test_aggregated_report_json_passthrough(self):
        from tinc_route_analyzer import flowcsv
        analysis, stats = flowcsv.analyze_flow_texts([("network.csv", None, FLOW_CSV)])
        report = json.dumps(flowcsv.to_dict(analysis, stats))
        res = analyze_payload({"files": [{"name": "report.json", "content": report}]})
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "flow")
        self.assertTrue(res.get("fromReport"))
        self.assertEqual(res["data"]["meta"]["hosts"], 2)

    def test_oversized_csv_redirects_to_cli(self):
        big = ("frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,ip.proto,frame.len\n"
               '"Jun 16, 2026 14:07:00.1 KST",10.0.0.1,10.0.0.2,665,40000,6,100\n'
               + "#" * (65 * 1024 * 1024))
        res = analyze_payload({"files": [{"name": "big.csv", "content": big}]})
        self.assertFalse(res["ok"])
        self.assertIn("tinc-flow-analyzer", res["error"])

    def test_tinc_still_routed_to_tinc_mode(self):
        res = analyze_payload({"files": [
            {"name": "linux_hq.log", "node": "hq", "content": HQ_LOG}]})
        self.assertEqual(res["mode"], "tinc")


if __name__ == "__main__":
    unittest.main()
