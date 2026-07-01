"""Tests for the security/bug/perf hardening pass."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinc_route_analyzer import flowcsv, job                      # noqa: E402
from tinc_route_analyzer.flowcsv import _parse_flags              # noqa: E402
from tinc_route_analyzer.web import server as websrv, updater     # noqa: E402

H = ("frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,"
     "tcp.flags,ip.proto,frame.len\n")


class TestParseFlagsHex(unittest.TestCase):
    def test_bare_and_prefixed_hex(self):
        self.assertEqual(_parse_flags("0x0002", None, None), (True, False))   # SYN
        self.assertEqual(_parse_flags("0x0012", None, None), (True, True))    # SYN-ACK
        self.assertEqual(_parse_flags("0002", None, None), (True, False))
        self.assertEqual(_parse_flags("10", None, None), (False, True))       # 0x10 = ACK
        self.assertEqual(_parse_flags("zz", None, None), (None, None))


class TestHotPathEquivalence(unittest.TestCase):
    def test_parallel_equals_sequential_forced_chunks(self):
        rows = "".join(
            "Jun 16 2026 10:%02d:%02d.0 KST,10.0.0.%d,10.0.0.%d,5%03d,443,,,0x0010,6,%d\n"
            % (i // 60 % 60, i % 60, i % 20, (i + 7) % 20, i % 1000, 100 + i % 500)
            for i in range(3000))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.csv")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(H + rows)
            units = flowcsv._build_units(p, 4, True, 4096)     # tiny chunk -> many units
            self.assertGreater(len(units), 1)                  # actually parallelized
            seq, _ = flowcsv.analyze_flow_files([p], workers=1)
            par, _ = flowcsv.analyze_flow_files([p], workers=4, target_chunk=4096)
            self.assertEqual(seq.packets, par.packets)
            self.assertEqual(flowcsv.to_dict(seq), flowcsv.to_dict(par))   # bit-identical


class TestFilterAnalysisHosts(unittest.TestCase):
    def test_service_hosts_kept_in_inventory(self):
        an = flowcsv.FlowAnalysis()
        an.services[("10.0.0.2", 6, 665)] = {
            "server": "10.0.0.2", "proto": 6, "port": 665,
            "clients": {"10.0.0.7"}, "packets": 5, "bytes": 100, "basis": "handshake"}
        flt = flowcsv.FlowFilter(exclude_src=["10.9.9.9"])     # active, excludes nothing here
        out = flowcsv.filter_analysis(an, flt)
        self.assertIn("10.0.0.2", out.hosts)                   # server present in inventory
        self.assertIn("10.0.0.7", out.hosts)                   # client present too
        d = flowcsv.to_dict(out)
        self.assertTrue(any(s["server"] == "10.0.0.2" for s in d["services"]))


class TestSnapshotRegex(unittest.TestCase):
    def test_nongreedy_host(self):
        self.assertEqual(job._SNAP_RE.match("srv1_flow_day_2026-06-18.json").group("host"), "srv1")
        self.assertIsNone(job._SNAP_RE.match("flow_day_2026-06-18.json").group("host"))
        self.assertEqual(job._SNAP_RE.match("srv_prod_flow_hour_2026.json.gz").group("host"), "srv_prod")


class TestUpdaterUrlGuard(unittest.TestCase):
    def test_scheme_allowlist(self):
        self.assertTrue(updater._is_http_url("http://x/y"))
        self.assertTrue(updater._is_http_url("HTTPS://x/y"))
        self.assertFalse(updater._is_http_url("file:///etc/passwd"))
        self.assertFalse(updater._is_http_url("ftp://x"))
        self.assertFalse(updater._is_http_url(""))
        data, err = updater.fetch_remote_versions("file:///etc")
        self.assertIsNone(data)
        self.assertTrue(err)
        self.assertFalse(updater.download_archive("file:///x-1.0.0.zip", "/tmp")["ok"])


class TestInputHardening(unittest.TestCase):
    def test_iface_regex(self):
        for good in ("tun0", "eth0.100", "br-lan", "ens192", "wg0"):
            self.assertTrue(websrv._IFACE_RE.match(good), good)
        for bad in ("a{b}", "a@b", "a\\b", "x" * 49, ""):
            self.assertFalse(websrv._IFACE_RE.match(bad), bad)

    def test_year_out_of_range_does_not_crash(self):
        payload = {"files": [{"name": "x.log", "content":
                   "Jun 16 10:20:03 hq tinc.o[1]: Connection with b (198.51.100.22 port 655) activated\n"}],
                   "year": 10 ** 12}
        r = websrv.analyze_payload(payload)
        self.assertTrue(r["ok"])


class TestAtomicWrite(unittest.TestCase):
    def test_roundtrip_no_leftover_tmp(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cfg.json")
            websrv._atomic_write_json(p, {"a": 1, "b": [2, 3]})
            with open(p, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), {"a": 1, "b": [2, 3]})
            self.assertEqual([f for f in os.listdir(d) if f.endswith(".tmp")], [])


if __name__ == "__main__":
    unittest.main()
