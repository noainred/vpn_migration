"""Tests for the analysis exclusion filter (re-analysis conditions + top-N)."""

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinc_route_analyzer import flowcsv, job  # noqa: E402
from tinc_route_analyzer.web import server as websrv  # noqa: E402

H = ("frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,"
     "tcp.flags,ip.proto,frame.len\n")
CSV = H + "".join([
    "Jun 16 2026 10:00:00.0 KST,10.0.0.10,10.0.0.20,51000,443,,,0x0002,6,100\n",   # tcp 443 SYN
    "Jun 16 2026 10:00:00.1 KST,10.0.0.20,10.0.0.10,443,51000,,,0x0012,6,100\n",   # tcp SYN-ACK
    "Jun 16 2026 10:00:01.0 KST,10.0.0.11,10.0.0.20,52000,443,,,0x0010,6,100\n",   # tcp 443
    "Jun 16 2026 10:00:02.0 KST,10.0.0.10,10.0.0.30,,,53000,53,,17,80\n",          # udp 53
    "Jun 16 2026 10:00:03.0 KST,192.168.1.5,10.0.0.20,52001,443,,,0x0010,6,100\n",  # tcp from 192.168/16
])


def _analyze(text, spec=None):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.csv")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return flowcsv.analyze_flow_files(
            [p], workers=1, flow_filter=flowcsv.FlowFilter.from_spec(spec))


class TestFlowFilter(unittest.TestCase):
    def test_excludes_record_dimensions(self):
        recs = list(flowcsv.iter_flow_records(io.StringIO(CSV)))
        self.assertEqual(len(recs), 5)
        f = flowcsv.FlowFilter(exclude_src=["10.0.0.10"])
        self.assertEqual(sum(1 for r in recs if not f.excludes_record(r)), 3)
        f = flowcsv.FlowFilter(exclude_dst=["10.0.0.30"])
        self.assertEqual(sum(1 for r in recs if not f.excludes_record(r)), 4)
        f = flowcsv.FlowFilter(exclude_proto=["udp"])
        self.assertEqual(sum(1 for r in recs if not f.excludes_record(r)), 4)
        f = flowcsv.FlowFilter(exclude_port=[443])
        self.assertEqual(sum(1 for r in recs if not f.excludes_record(r)), 1)
        f = flowcsv.FlowFilter(exclude_src=["192.168.0.0/16"])
        self.assertEqual(sum(1 for r in recs if not f.excludes_record(r)), 4)

    def test_from_spec_empty_is_none(self):
        self.assertIsNone(flowcsv.FlowFilter.from_spec(None))
        self.assertIsNone(flowcsv.FlowFilter.from_spec({}))
        self.assertIsNone(flowcsv.FlowFilter.from_spec(
            {"exclude_src": [], "exclude_port": []}))
        self.assertIsNotNone(flowcsv.FlowFilter.from_spec({"limit": 5}))

    def test_analyze_applies_filter(self):
        a, _ = _analyze(CSV)
        self.assertEqual(a.packets, 5)
        a, _ = _analyze(CSV, {"exclude_src": ["10.0.0.10"]})
        self.assertEqual(a.packets, 3)
        a, _ = _analyze(CSV, {"exclude_proto": ["udp"]})
        self.assertEqual(a.packets, 4)
        a, _ = _analyze(CSV, {"exclude_port": [443]})
        self.assertEqual(a.packets, 1)


class TestLimit(unittest.TestCase):
    def test_to_dict_limit_caps_lists_not_counts(self):
        a, _ = _analyze(CSV)
        full = flowcsv.to_dict(a)
        self.assertEqual(len(full["conversations"]), 4)
        capped = flowcsv.to_dict(a, limit=2)
        self.assertEqual(len(capped["conversations"]), 2)        # list truncated
        self.assertEqual(capped["meta"]["conversations"], 4)     # count is the full set
        self.assertEqual(capped["meta"]["limit"], 2)
        self.assertEqual(capped["meta"]["shown"]["conversations"], 2)


class TestFilterAnalysisMerge(unittest.TestCase):
    def _merged(self):
        a, s = flowcsv.analyze_flow_texts([("c", None, CSV)])
        rep = flowcsv.to_dict(a, s)
        return flowcsv.merge_reports([rep, rep]), rep  # two identical servers

    def test_endpoint_exclusion_recomputes(self):
        an, rep = self._merged()
        self.assertEqual(an.packets, 2 * rep["meta"]["packets"])   # 10
        flt = flowcsv.FlowFilter(exclude_dst=["10.0.0.30"])
        out = flowcsv.filter_analysis(an, flt)
        # the only conversation touching 10.0.0.30 carried 1 packet per server.
        self.assertEqual(out.packets, an.packets - 2)
        self.assertNotIn("10.0.0.30", out.hosts)
        self.assertFalse(any("10.0.0.30" in (k[0], k[1]) for k in out.convs))

    def test_proto_exclusion_drops_service_keeps_conv(self):
        an, _ = self._merged()
        flt = flowcsv.FlowFilter(exclude_proto=["udp"])
        out = flowcsv.filter_analysis(an, flt)
        # aggregate input: the UDP/53 service is removed...
        self.assertFalse(any(proto == 17 for (_s, proto, _p) in out.services))
        # ...but the conversation itself is retained (can't split bytes per-proto).
        self.assertTrue(any("10.0.0.30" in (k[0], k[1]) for k in out.convs))


class TestJobWithFilter(unittest.TestCase):
    def test_analyze_filter_basis_packet(self):
        with tempfile.TemporaryDirectory() as d:
            cap = os.path.join(d, "c.csv")
            with open(cap, "w", encoding="utf-8") as fh:
                fh.write(CSV)
            rc = job.run([cap], d, filter_spec={"exclude_proto": ["udp"]})
            self.assertEqual(rc, 0)
            with open(os.path.join(d, job.REPORT_NAME), encoding="utf-8") as fh:
                rep = json.load(fh)
            self.assertEqual(rep["meta"]["packets"], 4)
            self.assertEqual(rep["meta"]["filter_basis"], "packet")
            self.assertIn("UDP", rep["meta"]["filter"]["exclude_proto"])

    def test_merge_filter_basis_aggregate(self):
        a, s = flowcsv.analyze_flow_texts([("c", None, CSV)])
        rep = flowcsv.to_dict(a, s)
        with tempfile.TemporaryDirectory() as d:
            for n in ("s1.json", "s2.json"):
                with open(os.path.join(d, n), "w", encoding="utf-8") as fh:
                    json.dump(rep, fh)
            rc = job.run([os.path.join(d, "s1.json"), os.path.join(d, "s2.json")],
                         d, merge=True, filter_spec={"exclude_dst": ["10.0.0.30"]})
            self.assertEqual(rc, 0)
            with open(os.path.join(d, job.REPORT_NAME), encoding="utf-8") as fh:
                merged = json.load(fh)
            self.assertEqual(merged["meta"]["filter_basis"], "aggregate")
            self.assertEqual(merged["meta"]["packets"], 2 * rep["meta"]["packets"] - 2)


class TestServerFilterValidation(unittest.TestCase):
    def test_clean_filter_spec_flags_bad(self):
        spec, bad = websrv._clean_filter_spec({
            "exclude_src": ["10.0.0.5", "nope!!"], "exclude_proto": ["tcp", "zzz"],
            "exclude_port": ["443", "99999"], "limit": "5"})
        self.assertIn("nope!!", bad)
        self.assertIn("zzz", bad)
        self.assertIn("99999", bad)
        self.assertEqual(spec["limit"], 5)

    def test_clean_filter_spec_valid(self):
        spec, bad = websrv._clean_filter_spec({
            "exclude_src": ["10.0.0.5", "10.93.0.0/16"], "exclude_proto": ["tcp", "17"],
            "exclude_port": ["443"], "limit": 100})
        self.assertEqual(bad, [])
        self.assertTrue(websrv._filter_has_content(spec))
        self.assertEqual(spec["limit"], 100)

    def test_filter_persistence_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            saved = websrv._ANALYSIS_FILTER_PATH
            websrv._ANALYSIS_FILTER_PATH = os.path.join(d, "analysis_filter.json")
            try:
                spec, _ = websrv._clean_filter_spec(
                    {"exclude_src": ["10.0.0.9"], "limit": 50})
                websrv._save_analysis_filter(spec)
                loaded = websrv._load_analysis_filter()
                self.assertEqual(loaded["exclude_src"], ["10.0.0.9"])
                self.assertEqual(loaded["limit"], 50)
            finally:
                websrv._ANALYSIS_FILTER_PATH = saved


if __name__ == "__main__":
    unittest.main()
