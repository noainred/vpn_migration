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


class TestLiveCapture(unittest.TestCase):
    """Live capture core, exercised without tshark via fed/synthetic lines."""

    def _cap(self):
        from tinc_route_analyzer.web.server import LiveCapture
        return LiveCapture()

    def test_feed_and_snapshot(self):
        cap = self._cap()
        cap.feed_lines(FLOW_CSV.splitlines())
        snap = cap.snapshot()
        self.assertEqual(snap["data"]["meta"]["hosts"], 2)
        self.assertEqual(snap["data"]["mode"], "flow")
        self.assertFalse(snap["running"])

    def test_start_with_fake_source_thread(self):
        cap = self._cap()
        lines = FLOW_CSV.splitlines()
        ok, err = cap._start(lambda: iter(lines), "test0")
        self.assertTrue(ok)
        cap.thread.join(timeout=3)
        snap = cap.snapshot()
        self.assertEqual(snap["data"]["meta"]["hosts"], 2)
        self.assertFalse(snap["running"])

    def test_export_formats(self):
        cap = self._cap()
        cap.feed_lines(FLOW_CSV.splitlines())
        text, ctype = cap.export("conversations")
        self.assertIn("node_a,node_b", text)
        self.assertEqual(ctype, "text/csv")
        self.assertEqual(cap.export("bogus"), (None, None))

    def test_udp_ports_via_secondary_columns(self):
        # header with both tcp and udp port columns; a UDP row uses udp ports.
        from tinc_route_analyzer import flowcsv
        text = (
            "frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,ip.proto,frame.len\n"
            '"Jun 16, 2026 14:07:00.1 KST",10.0.0.9,10.0.0.1,,,40000,655,17,120\n')
        analysis, _ = flowcsv.analyze_flow_texts([("u.csv", None, text)])
        d = flowcsv.to_dict(analysis)
        self.assertEqual(d["services"][0]["service"], "UDP/655")
        self.assertEqual(d["services"][0]["server"], "10.0.0.1")


class TestPersistenceAndDashboard(unittest.TestCase):
    def test_system_stats_keys(self):
        from tinc_route_analyzer.web import persistence
        st = persistence.system_stats(".")
        for k in ("cpu_percent", "rss_bytes", "disk", "saved"):
            self.assertIn(k, st)
        self.assertIn("free", st["disk"])
        self.assertGreater(st["rss_bytes"], 0)

    def test_persistence_set_config_and_snapshot(self):
        import tempfile
        from tinc_route_analyzer.web import persistence
        with tempfile.TemporaryDirectory() as tmp:
            captured = {"meta": {"packets": 5}, "conversations": [], "hosts": []}
            p = persistence.Persistence(lambda: captured)
            cfg = p.set_config({"save_dir": tmp, "minute": True, "retention": 0})
            self.assertEqual(cfg["save_dir"], os.path.abspath(tmp))
            p._tick()  # one cadence pass; should write a minute snapshot
            files = [f for f in os.listdir(tmp) if f.startswith("flow_min")]
            self.assertEqual(len(files), 1)
            # no data -> no write
            p2 = persistence.Persistence(lambda: {"meta": {"packets": 0}})
            p2.set_config({"save_dir": tmp, "minute": True})
            before = len(os.listdir(tmp))
            p2._tick()
            self.assertEqual(len(os.listdir(tmp)), before)

    def test_retention_keeps_last_n(self):
        import tempfile
        from tinc_route_analyzer.web import persistence
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                open(os.path.join(tmp, "flow_min_x%02d.json" % i), "w").close()
            p = persistence.Persistence(lambda: None)
            p._retain(tmp, "minute", 2)
            self.assertEqual(len([f for f in os.listdir(tmp) if f.startswith("flow_min")]), 2)


class TestSnapshotCompressionAndPreview(unittest.TestCase):
    def test_compressed_write_list_and_head(self):
        import tempfile
        from tinc_route_analyzer.web import persistence
        with tempfile.TemporaryDirectory() as tmp:
            data = {"meta": {"packets": 3}, "conversations": [{"a": "10.0.0.1"}], "hosts": []}
            p = persistence.Persistence(lambda: data)
            p.set_config({"save_dir": tmp, "minute": True, "compress": True})
            p._tick()
            files = persistence.list_files(tmp)
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0]["name"].endswith(".json.gz"))
            lines = persistence.head_file(tmp, files[0]["name"], 100)
            self.assertTrue(lines and lines[0].startswith("{"))

    def test_head_file_rejects_traversal(self):
        import tempfile
        from tinc_route_analyzer.web import persistence
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(persistence.head_file(tmp, "../../etc/passwd"))
            self.assertIsNone(persistence.head_file(tmp, "notes.txt"))
            self.assertIsNone(persistence.head_file(tmp, "flow_min_x.json"))  # absent


class TestMultiReportMergeAndLast(unittest.TestCase):
    def test_analyze_payload_merges_multiple_reports(self):
        from tinc_route_analyzer import flowcsv
        a, _ = flowcsv.analyze_flow_texts([("network.csv", None, FLOW_CSV)])
        rep = json.dumps(flowcsv.to_dict(a))
        res = analyze_payload({"files": [
            {"name": "s1.json", "content": rep},
            {"name": "s2.json", "content": rep}]})
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "flow")
        self.assertTrue(res.get("merged"))
        self.assertEqual(res["mergedCount"], 2)
        # one conversation, deduped; packets doubled
        self.assertEqual(res["data"]["meta"]["conversations"], 1)


class TestUpdater(unittest.TestCase):
    def test_archive_round_trip_and_only_newer(self):
        import io, tarfile, tempfile
        from tinc_route_analyzer.web import updater
        with tempfile.TemporaryDirectory() as tmp:
            code = os.path.join(tmp, "code")
            os.makedirs(os.path.join(code, "tinc_route_analyzer"))
            with open(os.path.join(code, "tinc_route_analyzer", "__init__.py"), "w") as fh:
                fh.write('__version__ = "1.0.0"\n')
            arc = os.path.join(tmp, "tinc_route_analyzer-2.0.0.tar.gz")
            with tarfile.open(arc, "w:gz") as tf:
                d = b'__version__ = "2.0.0"\n'
                ti = tarfile.TarInfo("tinc_route_analyzer/__init__.py"); ti.size = len(d)
                tf.addfile(ti, io.BytesIO(d))
            self.assertEqual(updater.find_newer_archive(tmp, "1.0.0")[1], (2, 0, 0))
            res = updater.upgrade_from_archive(arc, code, "1.0.0")
            self.assertTrue(res["ok"]) ; self.assertEqual(res["version"], "2.0.0")
            self.assertIn('2.0.0', open(os.path.join(code, "tinc_route_analyzer", "__init__.py")).read())
            self.assertFalse(updater.upgrade_from_archive(arc, code, "9.0.0")["ok"])

    def test_path_escape_member_rejected(self):
        from tinc_route_analyzer.web import updater
        self.assertIsNone(updater._accept_member("tinc_route_analyzer/../evil.py"))
        self.assertIsNone(updater._accept_member("other_pkg/x.py"))
        self.assertEqual(updater._accept_member("tinc_route_analyzer/web/server.py"), "web/server.py")

    def test_unattended_auto_apply_restart(self):
        import io, tarfile, tempfile
        from tinc_route_analyzer.web import updater
        with tempfile.TemporaryDirectory() as tmp:
            code = os.path.join(tmp, "code")
            os.makedirs(os.path.join(code, "tinc_route_analyzer"))
            with open(os.path.join(code, "tinc_route_analyzer", "__init__.py"), "w") as fh:
                fh.write('__version__ = "1.0.0"\n')
            watch = os.path.join(tmp, "watch"); os.makedirs(watch)
            arc = os.path.join(watch, "tinc_route_analyzer-2.0.0.tar.gz")
            with tarfile.open(arc, "w:gz") as tf:
                d = b'__version__ = "2.0.0"\n'
                ti = tarfile.TarInfo("tinc_route_analyzer/__init__.py"); ti.size = len(d)
                tf.addfile(ti, io.BytesIO(d))
            mgr = updater.UpdateManager(lambda: "1.0.0", code)
            mgr.set_config({"enabled": True, "watch_dir": watch,
                            "auto_apply": True, "auto_restart": True})
            calls = {"n": 0}
            orig = updater.restart_process
            updater.restart_process = lambda: calls.__setitem__("n", calls["n"] + 1)
            try:
                mgr._tick_update()                      # applies + "restarts"
                self.assertEqual(calls["n"], 1)
                self.assertTrue(mgr.last["pending_restart"])
                mgr._tick_update()                      # guarded: no second apply/restart
                self.assertEqual(calls["n"], 1)
            finally:
                updater.restart_process = orig
            self.assertIn('2.0.0', open(os.path.join(code, "tinc_route_analyzer", "__init__.py")).read())

    def test_config_never_exposes_token(self):
        import tempfile
        from tinc_route_analyzer.web import updater
        with tempfile.TemporaryDirectory() as tmp:
            mgr = updater.UpdateManager(lambda: "1.0.0", tmp)
            mgr.set_config({"enabled": True, "token": "secret-pat", "remote_base": "https://x/y"})
            cfg = mgr.get_config()
            self.assertNotIn("token", cfg)
            self.assertTrue(cfg["has_token"])
            self.assertTrue(cfg["enabled"])


class TestScanBackendDecoupling(unittest.TestCase):
    def test_live_json_contract(self):
        import tempfile, time
        from tinc_route_analyzer import scan, flowcsv
        from tinc_route_analyzer.web.server import ScanController
        with tempfile.TemporaryDirectory() as tmp:
            a, _ = flowcsv.analyze_flow_texts([("n", None, FLOW_CSV)])
            scan.write_live(os.path.join(tmp, "live.json"), {
                "running": True, "iface": "tun0", "started": time.time(),
                "heartbeat": time.time(), "pid": os.getpid(), "packets": 2,
                "pps": 1.0, "error": "", "data": flowcsv.to_dict(a)})
            sc = ScanController(tmp)
            self.assertTrue(sc.is_running())               # fresh + this pid alive
            self.assertEqual(sc.snapshot()["iface"], "tun0")
            self.assertEqual(len(sc.data()["hosts"]), 2)
            self.assertIn("node_a", sc.export("conversations")[0])

    def test_stale_or_dead_backend_not_running(self):
        import tempfile, time
        from tinc_route_analyzer import scan
        from tinc_route_analyzer.web.server import ScanController
        with tempfile.TemporaryDirectory() as tmp:
            sc = ScanController(tmp)
            self.assertFalse(sc.is_running())              # no file
            scan.write_live(os.path.join(tmp, "live.json"), {
                "running": True, "heartbeat": time.time() - 60, "pid": os.getpid(),
                "data": {}})
            self.assertFalse(sc.is_running())              # stale heartbeat

    def test_scan_argv_includes_validated_filter(self):
        from tinc_route_analyzer import scan
        argv = scan._tshark_argv("tun0", "not (host 10.0.0.1)")
        self.assertEqual(argv[:3], ["tshark", "-i", "tun0"])
        self.assertIn("-f", argv)
        self.assertIn("not (host 10.0.0.1)", argv)


class TestCaptureExclude(unittest.TestCase):
    def test_validation_and_filter(self):
        from tinc_route_analyzer.web import server
        self.assertTrue(server._valid_exclude("10.0.0.1"))
        self.assertTrue(server._valid_exclude("10.93.0.0/16"))
        self.assertFalse(server._valid_exclude("evil; rm -rf"))
        self.assertFalse(server._valid_exclude("host 1.2.3.4"))
        self.assertEqual(server._build_capture_filter([]), "")
        self.assertEqual(server._build_capture_filter(["10.0.0.1", "10.93.0.0/16"]),
                         "not (host 10.0.0.1 or net 10.93.0.0/16)")


if __name__ == "__main__":
    unittest.main()
