"""Tests for the tshark/Wireshark CSV flow analyzer (the real capture format)."""

import gzip
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinc_route_analyzer import flowcsv  # noqa: E402

SAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "network.csv")


def _sample_text():
    with open(SAMPLE, encoding="utf-8") as fh:
        return fh.read()


class TestParsing(unittest.TestCase):
    def test_quoted_time_with_embedded_comma(self):
        # frame.time contains a comma inside quotes; csv must keep it one field.
        line = '"Jun 16, 2026 14:07:00.649943933 KST",10.94.40.36,10.93.168.39,665,41884,6,138'
        recs = list(flowcsv.iter_flow_records([
            "frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,ip.proto,frame.len",
            line]))
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r.src, "10.94.40.36")
        self.assertEqual(r.dst, "10.93.168.39")
        self.assertEqual((r.sport, r.dport), (665, 41884))
        self.assertEqual(r.proto, 6)
        self.assertEqual(r.length, 138)
        self.assertEqual(r.time.year, 2026)
        self.assertEqual(r.time.microsecond, 649943)  # ns truncated to us

    def test_parse_time(self):
        dt = flowcsv.parse_time("Jun 16, 2026 14:07:00.650003566 KST")
        self.assertEqual((dt.month, dt.day, dt.hour, dt.minute, dt.second), (6, 16, 14, 7, 0))

    def test_looks_like_flow_csv(self):
        self.assertTrue(flowcsv.looks_like_flow_csv(_sample_text()))
        self.assertTrue(flowcsv.looks_like_flow_csv("10.0.0.1,10.0.0.2,80,12345,6,100"))
        self.assertFalse(flowcsv.looks_like_flow_csv(
            "Jun 16 10:20:01 hq tinc.office[1010]: Connection with cloud (1.2.3.4 port 655) activated"))


class TestServicePortFacts(unittest.TestCase):
    """Server port determined from documented port ranges, never guessed."""

    def test_well_known_vs_ephemeral(self):
        self.assertEqual(flowcsv._service_port(665, 41884, 6), 665)
        self.assertEqual(flowcsv._service_port(43593, 665, 6), 665)

    def test_undetermined_when_same_class(self):
        # both ephemeral -> cannot know initiator without flags -> None
        self.assertIsNone(flowcsv._service_port(50000, 51000, 6))
        # both well-known -> undetermined
        self.assertIsNone(flowcsv._service_port(80, 443, 6))

    def test_non_port_protocol(self):
        self.assertIsNone(flowcsv._service_port(None, None, 1))  # ICMP

    def test_port_class(self):
        self.assertEqual(flowcsv.port_class(665), "well-known")
        self.assertEqual(flowcsv.port_class(41884), "registered")
        self.assertEqual(flowcsv.port_class(54237), "dynamic")


class TestSampleAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analysis, cls.stats = flowcsv.analyze_flow_texts(
            [("network.csv", None, _sample_text())])
        cls.d = flowcsv.to_dict(cls.analysis, cls.stats)

    def test_counts(self):
        self.assertEqual(self.d["meta"]["hosts"], 6)
        self.assertEqual(self.d["meta"]["conversations"], 5)
        self.assertEqual(self.d["meta"]["packets"], 35)

    def test_conversation_dedup_and_direction(self):
        # A<->B merged into one conversation, with per-direction split.
        convs = {frozenset((c["a"], c["b"])): c for c in self.d["conversations"]}
        c = convs[frozenset(("10.94.40.36", "10.95.113.39"))]
        self.assertEqual(c["packets"], 5)        # not 10 (no double counting)
        self.assertEqual(c["bytes"], 578)
        self.assertEqual(c["a_to_b_packets"] + c["b_to_a_packets"], 5)
        self.assertEqual(c["a_to_b_packets"], 3)  # 10.94.40.36 -> 10.95.113.39
        self.assertEqual(c["b_to_a_packets"], 2)

    def test_services_factual(self):
        svc = {(s["server"], s["port"]): s for s in self.d["services"]}
        # 10.94.40.36 serves TCP/665 to four ephemeral-port clients
        s1 = svc[("10.94.40.36", 665)]
        self.assertEqual(s1["proto"], "TCP")
        self.assertEqual(s1["client_count"], 4)
        self.assertIn("10.93.124.39", s1["clients"])
        # 10.95.113.39 also listens on 665; its only client here is 10.94.40.36
        s2 = svc[("10.95.113.39", 665)]
        self.assertEqual(s2["clients"], ["10.94.40.36"])
        self.assertEqual(s2["port_class"], "well-known")

    def test_host_roles(self):
        roles = {h["ip"]: h["role"] for h in self.d["hosts"]}
        self.assertEqual(roles["10.95.113.39"], "server")   # only ever listens
        self.assertEqual(roles["10.93.168.39"], "client")   # only ephemeral ports
        self.assertEqual(roles["10.94.40.36"], "both")      # serves and connects

    def test_subnet_matrix(self):
        pairs = {frozenset((m["a"], m["b"])) for m in self.d["subnet_matrix"]}
        self.assertIn(frozenset(("10.94.40.0/24", "10.93.124.0/24")), pairs)

    def test_exports(self):
        self.assertIn("node_a,node_b", flowcsv.render_conversations_csv(self.analysis).splitlines()[0])
        self.assertIn("policy,action", flowcsv.render_policies_csv(self.analysis).splitlines()[0])
        self.assertTrue(flowcsv.render_dot(self.analysis).startswith("digraph"))


class TestHandshakeDetection(unittest.TestCase):
    """TCP handshake (SYN/SYN-ACK) gives a factual server determination."""

    H = "frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,tcp.flags,ip.proto,frame.len\n"

    def _one(self, row):
        a, _ = flowcsv.analyze_flow_texts([("s.csv", None, self.H + row + "\n")])
        return flowcsv.to_dict(a)["services"]

    def test_syn_resolves_ambiguous_ports(self):
        # both ports ephemeral -> port-range alone is undetermined (no service);
        # the SYN makes the destination the server (fact).
        svcs = self._one('"Jun 16, 2026 14:07:00.1 KST",10.0.0.9,10.0.0.1,50000,50001,0x0002,6,74')
        self.assertEqual(len(svcs), 1)
        self.assertEqual((svcs[0]["server"], svcs[0]["port"]), ("10.0.0.1", 50001))
        self.assertEqual(svcs[0]["basis"], "handshake")

    def test_without_flags_same_ports_undetermined(self):
        text = ("frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,ip.proto,frame.len\n"
                '"Jun 16, 2026 14:07:00.1 KST",10.0.0.9,10.0.0.1,50000,50001,6,74\n')
        a, _ = flowcsv.analyze_flow_texts([("s.csv", None, text)])
        self.assertEqual(flowcsv.to_dict(a)["services"], [])  # no guess

    def test_synack_source_is_server(self):
        svcs = self._one('"Jun 16, 2026 14:07:00.1 KST",10.0.0.1,10.0.0.9,50001,50000,0x0012,6,74')
        self.assertEqual((svcs[0]["server"], svcs[0]["port"]), ("10.0.0.1", 50001))
        self.assertEqual(svcs[0]["basis"], "handshake")

    def test_handshake_outranks_port_range(self):
        # SYN from :665 -> :40000 means 665 is the CLIENT side here; the server
        # is the SYN destination (10.0.0.9:40000), overriding the port heuristic.
        svcs = self._one('"Jun 16, 2026 14:07:00.1 KST",10.0.0.1,10.0.0.9,665,40000,0x0002,6,74')
        self.assertEqual((svcs[0]["server"], svcs[0]["port"]), ("10.0.0.9", 40000))
        self.assertEqual(svcs[0]["basis"], "handshake")

    def test_boolean_flag_columns(self):
        text = ("frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,tcp.flags.syn,tcp.flags.ack,ip.proto,frame.len\n"
                '"Jun 16, 2026 14:07:00.1 KST",10.0.0.9,10.0.0.1,50000,50001,1,0,6,74\n')
        a, _ = flowcsv.analyze_flow_texts([("s.csv", None, text)])
        s = flowcsv.to_dict(a)["services"][0]
        self.assertEqual((s["server"], s["port"], s["basis"]), ("10.0.0.1", 50001, "handshake"))

    def test_parse_flags_helper(self):
        self.assertEqual(flowcsv._parse_flags("0x0002", None, None), (True, False))
        self.assertEqual(flowcsv._parse_flags("0x0012", None, None), (True, True))
        self.assertEqual(flowcsv._parse_flags("0x0010", None, None), (False, True))
        self.assertEqual(flowcsv._parse_flags(None, "1", "0"), (True, False))


class TestStreamingFromDisk(unittest.TestCase):
    def test_file_matches_text(self):
        a1, _ = flowcsv.analyze_flow_texts([("network.csv", None, _sample_text())])
        a2, stats = flowcsv.analyze_flow_files([SAMPLE])
        self.assertEqual(a1.packets, a2.packets)
        self.assertEqual(len(a1.hosts), len(a2.hosts))
        self.assertEqual(stats["records"], a2.packets)

    def test_gzip_streaming(self):
        with tempfile.TemporaryDirectory() as tmp:
            gz = os.path.join(tmp, "network.csv.gz")
            with gzip.open(gz, "wt", encoding="utf-8") as fh:
                fh.write(_sample_text())
            analysis, stats = flowcsv.analyze_flow_files([gz])
            self.assertEqual(analysis.packets, 35)
            self.assertEqual(stats["files"], 1)

    def test_render_from_aggregated_dict(self):
        # The portal renders a CLI-produced report.json without re-analysing.
        analysis, stats = flowcsv.analyze_flow_files([SAMPLE])
        d = flowcsv.to_dict(analysis, stats)
        self.assertIn("digraph", flowcsv.render_dot(d))
        self.assertIn("node_a,node_b", flowcsv.render_conversations_csv(d).splitlines()[0])


if __name__ == "__main__":
    unittest.main()
