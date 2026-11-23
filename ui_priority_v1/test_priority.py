"""Offline checks with synthetic fixtures. Never scan or call a model.

Run from project root: python ui_priority_v1/test_priority.py
"""
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parent
EXISTING = Path(os.environ.get("REVIEW_UI_TEST_BASE", str(PACKAGE.parent / "review_ui")))
sys.path[:0] = [str(EXISTING), str(PACKAGE / "review_ui")]
import app as ui
from jinja2 import FileSystemLoader


class PriorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.folder = self.root / "runs" / "demo"
        self.folder.mkdir(parents=True)
        self.old = ui.ROOT, ui.RUN_ROOTS, ui.app.jinja_loader
        ui.ROOT, ui.RUN_ROOTS = self.root, (("Test", self.root / "runs"),)
        ui.app.jinja_loader = FileSystemLoader([str(PACKAGE / "review_ui/templates"), str(EXISTING / "templates")])
        ui.app.config.update(TESTING=True)
        self.client = ui.app.test_client()
        self.manifest = {"state": "COMPLETED", "analysis_id": "test-analysis", "project": "Demo", "result_count": 3}
        self.rows = []
        self.reviews = {"version": 1, "history": []}
        for idx, (name, ai, system, rule) in enumerate([
            ("Trial03.java", "LIKELY_FP", "LIKELY_FP", "findsecbugs:SQL_INJECTION_JDBC"),
            ("PathCase01.java", "LIKELY_TP", "LIKELY_TP", "findsecbugs:PATH_TRAVERSAL_IN"),
            ("CommandCase02.java", "UNKNOWN", "LIKELY_FP", "findsecbugs:COMMAND_INJECTION")]):
            artifact = f"issue-{idx:04d}"
            (self.folder / artifact).mkdir()
            raw = b"public class Demo {\n    void run() {}\n}\n"
            (self.folder / artifact / "source.java.txt").write_bytes(raw)
            row = dict(issue_id=str(idx), component="demo:Clean_Code/" + name, line=2, rule=rule,
                       artifact_dir=artifact, source_sha256=hashlib.sha256(raw).hexdigest(),
                       processing_status="AI_PROPOSED", verdict=system, combined_verdict=system, ai_verdict=ai,
                       decision_origin="STATIC_GUARD" if idx == 2 else "AI_PIPELINE", error_kind=None,
                       explanation="Giải thích kiểm thử", ai_explanation="Giải thích AI kiểm thử",
                       evidence_lines=[2], missing_context=[])
            self.rows.append(row)
            self.add_review(row, system)
        self.write()

    def add_review(self, row, label):
        key = ui.review_key(self.manifest, row)
        revision = 1 + sum(r["record_key"] == key for r in self.reviews["history"])
        self.reviews["history"].append(dict(record_key=key, revision=revision, reviewed_verdict=label,
                                            reviewer="Khanh", notes="Đã đọc bằng chứng.", saved_at="2026-11-04T00:00:00Z"))

    def write(self):
        for name, data in (("manifest.json", self.manifest), ("ai_results.json", self.rows), ("reviews_ui.json", self.reviews)):
            (self.folder / name).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def queue(self):
        entries = ui.build_entries(self.folder, self.manifest, self.rows, self.reviews)
        return {g["key"]: g["items"] for g in ui.priority_queue.build_queue(entries)}

    def tearDown(self):
        ui.ROOT, ui.RUN_ROOTS, ui.app.jinja_loader = self.old
        self.tmp.cleanup()

    def test_reviewed_demo_and_read_only_routes(self):
        groups = self.queue()
        self.assertEqual([i["entry"]["filename"] for i in groups["act"]], ["PathCase01.java"])
        self.assertEqual(len(groups["reviewed_fp"]), 2)
        before = {p: p.read_bytes() for p in self.folder.rglob("*") if p.is_file()}
        with patch("subprocess.Popen", side_effect=AssertionError("No subprocess")), patch.object(ui.job_runner, "start_job", side_effect=AssertionError("No job")):
            for path in ("/priority", "/priority.csv"):
                response = self.client.get("/runs/0/demo" + path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(b"UNKNOWN", response.data)
        self.assertEqual(before, {p: p.read_bytes() for p in self.folder.rglob("*") if p.is_file()})

    def test_pending_disagreement_and_human_override(self):
        self.reviews["history"] = []
        groups = self.queue()
        self.assertEqual(len(groups["act"]), 1)
        self.assertEqual(len(groups["clarify"]), 1)  # AI UNKNOWN vs system FP
        self.assertEqual(len(groups["verify_fp"]), 1)
        self.add_review(self.rows[1], "UNKNOWN")
        groups = self.queue()
        self.assertEqual(len(groups["act"]), 0)
        self.assertEqual(len(groups["clarify"]), 2)
        self.add_review(self.rows[0], "LIKELY_TP")
        self.add_review(self.rows[1], "LIKELY_TP")
        groups = self.queue()
        self.assertEqual(len(groups["act"]), 2)
        self.assertTrue(all(i["human_valid"] for i in groups["act"]))

    def test_source_hash_and_exact_record_binding(self):
        (self.folder / "issue-0000/source.java.txt").write_text("changed source")
        groups = self.queue()
        self.assertEqual(len(groups["reviewed_fp"]), 1)
        self.assertFalse(groups["clarify"][0]["human_valid"])
        self.rows[2]["explanation"] = "Record was changed"
        groups = self.queue()
        self.assertEqual(len(groups["reviewed_fp"]), 0)
        self.assertEqual(len(groups["clarify"]), 2)
        self.manifest["analysis_id"] = "another-run"
        self.assertTrue(all(not i["human_valid"] for g in self.queue().values() for i in g))

    def test_abstained_error_skipped_and_incomplete(self):
        self.reviews["history"] = []
        self.rows[0].update(processing_status="ABSTAINED", error_kind="NO_MATCHING_FLOW", verdict="UNKNOWN", combined_verdict="UNKNOWN")
        self.rows[1]["error_kind"] = "OLLAMA_TIMEOUT"
        self.rows[2].update(processing_status="SKIPPED", error_kind="UNSUPPORTED_RULE")
        groups = self.queue()
        self.assertEqual(len(groups["clarify"]), 2)
        self.assertEqual(len(groups["outside"]), 1)
        self.add_review(self.rows[0], "LIKELY_FP")
        self.assertEqual(len(self.queue()["reviewed_fp"]), 1)  # a human may resolve abstention
        self.manifest["state"] = "IN_PROGRESS"
        groups = self.queue()
        self.assertEqual(len(groups["clarify"]), 2)
        self.assertEqual(len(groups["reviewed_fp"]), 0)

    def test_broken_reviews_never_lower_priority(self):
        (self.folder / "reviews_ui.json").write_text("{broken")
        response = self.client.get("/runs/0/demo/priority.csv")
        rows = list(csv.DictReader(io.StringIO(response.data.decode("utf-8-sig"))))
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r["group"].startswith("2 ·") for r in rows))
        self.assertTrue(all(not r["valid_reviewed_verdict"] for r in rows))

    def test_filter_escape_and_csv_formula(self):
        self.rows[0]["component"] = '=HYPERLINK("bad")<script>alert(1)</script>'
        self.write()
        response = self.client.get("/runs/0/demo/priority")
        self.assertNotIn(b"<script>", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        response = self.client.get("/runs/0/demo/priority.csv?group=verify_fp")
        rows = list(csv.DictReader(io.StringIO(response.data.decode("utf-8-sig"))))
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["component"].startswith("'="))
        self.assertEqual(self.client.get("/runs/0/demo/priority?group=bad").status_code, 400)

    def test_paths_and_missing_results(self):
        for path in ("/runs/2/demo/priority", "/runs/0/../priority"):
            self.assertEqual(self.client.get(path).status_code, 404)
        (self.root / "runs/link").symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.client.get("/runs/0/link/priority").status_code, 404)
        (self.folder / "ai_results.json").unlink()
        response = self.client.get("/runs/0/demo/priority")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Chưa có kết quả phân tích".encode(), response.data)
        (self.folder / "ai_results.json").write_text("not json")
        self.assertEqual(self.client.get("/runs/0/demo/priority").status_code, 409)

    def test_saved_review_updates_queue_and_existing_views(self):
        self.reviews["history"] = []
        self.write()
        for route in ("", "/statistics", "/report", "/export.csv", "/priority"):
            self.assertEqual(self.client.get("/runs/0/demo" + route).status_code, 200, route)
        with self.client.session_transaction() as session:
            csrf = session["csrf"]
        raw = (self.folder / "ai_results.json").read_bytes()
        response = self.client.post("/runs/0/demo/review/1", data={"csrf": csrf, "record_key": ui.review_key(self.manifest, self.rows[1]),
            "revision": "0", "reviewer": "Khanh", "reviewed_verdict": "LIKELY_FP", "notes": "Đã đối chiếu cơ chế bảo vệ trong mã nguồn."})
        self.assertEqual(response.status_code, 303)
        data = self.client.get("/runs/0/demo/priority.csv?group=reviewed_fp").data
        self.assertIn(b"PathCase01.java", data)
        self.assertEqual(raw, (self.folder / "ai_results.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
