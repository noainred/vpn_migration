"""Tests for the server-side analysis-job backend and its portal controller."""

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinc_route_analyzer import flowcsv, job  # noqa: E402
from tinc_route_analyzer.web.server import JobController  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(REPO, "samples", "network.csv")

CSV = (
    "frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,"
    "tcp.flags,ip.proto,frame.len\n"
    "Jun 16 2026 10:00:00.000000 KST,10.0.0.10,10.0.0.20,51000,443,,,0x0002,6,120\n"
    "Jun 16 2026 10:00:00.100000 KST,10.0.0.20,10.0.0.10,443,51000,,,0x0012,6,140\n"
    "Jun 16 2026 10:00:01.000000 KST,10.0.0.11,10.0.0.20,52000,443,,,0x0010,6,200\n"
)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class TestJobRun(unittest.TestCase):
    def test_analyze_writes_status_and_report(self):
        with tempfile.TemporaryDirectory() as d:
            cap = os.path.join(d, "cap.csv")
            _write(cap, CSV)
            rc = job.run([cap], d, workers=1)
            self.assertEqual(rc, 0)

            with open(os.path.join(d, job.STATUS_NAME), encoding="utf-8") as fh:
                status = json.load(fh)
            self.assertEqual(status["state"], "done")
            self.assertEqual(status["mode"], "analyze")
            self.assertEqual(status["files_total"], 1)
            self.assertEqual(status["packets"], 3)
            self.assertIn("summary", status)

            with open(os.path.join(d, job.REPORT_NAME), encoding="utf-8") as fh:
                report = json.load(fh)
            self.assertEqual(report["mode"], "flow")
            self.assertEqual(report["meta"]["packets"], 3)
            # 443 over a TCP handshake (SYN then SYN-ACK) is a fact-based service.
            self.assertTrue(any(s["port"] == 443 for s in report["services"]))
            self.assertTrue(any(s["basis"] == "handshake" for s in report["services"]))

    def test_glob_expansion(self):
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, "a.csv"), CSV)
            _write(os.path.join(d, "b.csv"), CSV)
            rc = job.run([os.path.join(d, "*.csv")], d, workers=1)
            self.assertEqual(rc, 0)
            with open(os.path.join(d, job.STATUS_NAME), encoding="utf-8") as fh:
                status = json.load(fh)
            self.assertEqual(status["files_total"], 2)
            self.assertEqual(status["packets"], 6)

    def test_missing_path_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            rc = job.run([os.path.join(d, "nope.csv")], d, workers=1)
            self.assertEqual(rc, 1)
            with open(os.path.join(d, job.STATUS_NAME), encoding="utf-8") as fh:
                status = json.load(fh)
            self.assertEqual(status["state"], "error")
            self.assertFalse(os.path.exists(os.path.join(d, job.REPORT_NAME)))

    def test_merge_consolidates_reports(self):
        analysis, stats = flowcsv.analyze_flow_texts([("c", None, CSV)])
        report = flowcsv.to_dict(analysis, stats)
        with tempfile.TemporaryDirectory() as d:
            r1 = os.path.join(d, "srv1.json")
            r2 = os.path.join(d, "srv2.json")
            _write(r1, json.dumps(report))
            _write(r2, json.dumps(report))
            rc = job.run([r1, r2], d, merge=True)
            self.assertEqual(rc, 0)
            with open(os.path.join(d, job.STATUS_NAME), encoding="utf-8") as fh:
                status = json.load(fh)
            self.assertEqual(status["state"], "done")
            self.assertEqual(status["mode"], "merge")
            with open(os.path.join(d, job.REPORT_NAME), encoding="utf-8") as fh:
                merged = json.load(fh)
            # Same pair on both servers -> deduplicated to one conversation,
            # but the packet/byte totals add up.
            self.assertEqual(merged["meta"]["packets"], 2 * report["meta"]["packets"])
            self.assertEqual(len(merged["conversations"]),
                             len(report["conversations"]))


class TestJobController(unittest.TestCase):
    def test_start_validates_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ok, err = JobController(d).start([])
            self.assertFalse(ok)
            self.assertTrue(err)

    def test_idle_status(self):
        with tempfile.TemporaryDirectory() as d:
            st = JobController(d).status()
            self.assertEqual(st["state"], "idle")
            self.assertFalse(st["running"])
            self.assertFalse(st["hasResult"])

    def test_status_and_result_from_files(self):
        # A controller reads whatever the (separate) job process wrote.
        with tempfile.TemporaryDirectory() as d:
            jc = JobController(d)
            cap = os.path.join(d, "cap.csv")
            _write(cap, CSV)
            job.run([cap], d, workers=1)        # produce job.json + report in-process
            st = jc.status()
            self.assertEqual(st["state"], "done")
            self.assertTrue(st["hasResult"])
            self.assertFalse(st["running"])      # heartbeat is stale / pid is us-but-done
            rep = jc.result()
            self.assertIsNotNone(rep)
            self.assertEqual(rep["meta"]["packets"], 3)

    def test_end_to_end_subprocess(self):
        if not os.path.exists(SAMPLE):
            self.skipTest("sample capture not present")
        with tempfile.TemporaryDirectory() as d:
            jc = JobController(d)
            ok, err = jc.start([SAMPLE], workers=1)
            self.assertTrue(ok, err)
            deadline = time.time() + 30
            while time.time() < deadline:
                st = jc.status()
                if st["state"] in ("done", "error", "canceled") and not st["running"]:
                    break
                time.sleep(0.2)
            st = jc.status()
            self.assertEqual(st["state"], "done", st.get("error"))
            self.assertTrue(st["hasResult"])
            rep = jc.result()
            self.assertEqual(rep["mode"], "flow")
            self.assertGreater(rep["meta"]["packets"], 0)


class TestDirectoryHandling(unittest.TestCase):
    def test_analyze_expands_directory(self):
        # Pointing analysis at a DIRECTORY must analyse the captures inside it,
        # not fail with "Is a directory" (the reported bug).
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "cap.csv"), "w", encoding="utf-8") as fh:
                fh.write(CSV)
            rc = job.run([d], d, workers=4)          # workers>1 = the crash path
            self.assertEqual(rc, 0)
            with open(os.path.join(d, job.STATUS_NAME), encoding="utf-8") as fh:
                st = json.load(fh)
            self.assertEqual(st["state"], "done")
            self.assertEqual(st["packets"], 3)

    def test_analyze_recurses_subdirectories(self):
        # Captures nested in subdirectories must be found; snapshot JSON skipped.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            sub = os.path.join(d, "2026", "06")
            os.makedirs(sub)
            with open(os.path.join(sub, "cap.csv"), "w", encoding="utf-8") as fh:
                fh.write(CSV)
            with open(os.path.join(d, "srv_flow_day_2026-06-18.json"), "w", encoding="utf-8") as fh:
                fh.write('{"mode":"flow"}')        # aggregated snapshot -> must be ignored
            rc = job.run([d], out, workers=1)
            self.assertEqual(rc, 0)
            with open(os.path.join(out, job.STATUS_NAME), encoding="utf-8") as fh:
                st = json.load(fh)
            self.assertEqual(st["state"], "done")
            self.assertEqual(st["packets"], 3)       # cap.csv in the subdir
            self.assertEqual(st["files_total"], 1)   # the snapshot JSON was skipped

    def test_directory_without_captures_is_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            rc = job.run([d], d, workers=1)
            self.assertEqual(rc, 1)
            with open(os.path.join(d, job.STATUS_NAME), encoding="utf-8") as fh:
                st = json.load(fh)
            self.assertEqual(st["state"], "error")

    def test_analyze_flow_files_skips_directory(self):
        with tempfile.TemporaryDirectory() as d:
            an, stats = flowcsv.analyze_flow_files([d], workers=4)
            self.assertEqual(an.packets, 0)
            self.assertTrue(any("director" in msg for _p, msg in stats["unreadable"]))


if __name__ == "__main__":
    unittest.main()
