"""Offline integration checks: real worker + local fake Ollama, no model calls.

After installation: python ui_patch_v1/test_patch.py
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

PACKAGE = Path(__file__).resolve().parent
EXISTING = Path(os.environ.get("REVIEW_UI_TEST_BASE", str(PACKAGE.parent / "review_ui")))
sys.path.insert(0, str(EXISTING))
import app as ui
import patch_core as core
import job_runner as jobs

SOURCE = '''package pilot_path22;
import java.io.File;
import java.io.FileInputStream;
public class PathCase01 {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("One argument required");
        String fileName = args[0];
        String fullPath = "/var/www/uploads/" + fileName;
        File file = new File(fullPath);
        try (FileInputStream input = new FileInputStream(file)) {
            System.out.println(input.read());
        }
    }
}
'''
UPDATED = SOURCE.replace("import java.io.File;", "import java.io.File;\nimport java.nio.file.Path;").replace(
    '        String fullPath = "/var/www/uploads/" + fileName;\n        File file = new File(fullPath);',
    '        Path base = Path.of("/var/www/uploads").toRealPath();\n'
    '        Path target = base.resolve(fileName).toRealPath();\n'
    '        if (!target.startsWith(base)) throw new IllegalArgumentException("Outside base");\n'
    '        File file = target.toFile();')


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.folder = self.root / "runs/demo"
        (self.folder / "issue-0000").mkdir(parents=True)
        self.relative = "Clean_Code/pilot_path22/PathCase01.java"
        (self.root / self.relative).parent.mkdir(parents=True)
        (self.root / self.relative).write_text(SOURCE)
        (self.folder / "issue-0000/source.java.txt").write_text(SOURCE)
        self.manifest = {"state": "COMPLETED", "analysis_id": "test-analysis", "project": "test", "result_count": 1}
        self.row = dict(issue_id="path-test", component="test:" + self.relative, rule="findsecbugs:PATH_TRAVERSAL_IN",
                        line=9, artifact_dir="issue-0000", source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
                        processing_status="AI_PROPOSED", ai_verdict="LIKELY_TP", combined_verdict="LIKELY_TP",
                        verdict="LIKELY_TP", decision_origin="AI_PIPELINE", explanation="Giải thích kiểm thử",
                        evidence_lines=[7,8,9,10], missing_context=[], error_kind=None)
        self.reviews = {"version": 1, "history": [dict(record_key=ui.review_key(self.manifest, self.row), revision=1,
            reviewed_verdict="LIKELY_TP", reviewer="Khanh", notes="Đã đối chiếu mã nguồn.", saved_at="2026-11-05T00:00:00Z")]}
        self.write()
        self.original_root, self.original_runs = ui.ROOT, ui.RUN_ROOTS
        ui.ROOT, ui.RUN_ROOTS = self.root, (("Test", self.root / "runs"),)
        ui.app.config.update(TESTING=True)
        self.client = ui.app.test_client()
        self.proposal = {"status": "DRAFT", "summary": "Bản trả lời giả lập phục vụ kiểm thử tích hợp.",
            "changes": ["Đối chiếu đường dẫn thực với thư mục gốc."], "updated_source": UPDATED,
            "assumptions": ["Thư mục gốc tin cậy; cần kiểm tra race nếu có người khác thay symlink."],
            "test_plan": ["Tệp hợp lệ trong base: vẫn đọc được.", "Đường dẫn ra ngoài base: bị từ chối."], "missing_context": []}
        self.body_override = {}
        self.calls, self.requests = 0, []
        self.entered = threading.Event()
        self.release = threading.Event(); self.release.set()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def send(self, data):
                raw = json.dumps(data).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def do_GET(self):
                owner.assertEqual(self.path, "/api/tags")
                self.send({"models": [{"name": core.MODEL, "digest": "test-digest"}]})
            def do_POST(self):
                owner.assertEqual(self.path, "/api/generate")
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append(req); owner.calls += 1; owner.entered.set()
                owner.release.wait(8)
                self.send({"model": req["model"], "done": True, "done_reason": "stop", "prompt_eval_count": 1200,
                           "response": json.dumps(owner.proposal, ensure_ascii=False), **owner.body_override})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.env = patch.dict(os.environ, {"OLLAMA_URL": f"http://127.0.0.1:{self.server.server_port}", "PATCH_MODEL": core.MODEL, "PATCH_TIMEOUT": "30"})
        self.env.start()
        self.job_ids = []

    def write(self):
        for name, data in (("manifest.json", self.manifest), ("ai_results.json", [self.row]), ("reviews_ui.json", self.reviews)):
            (self.folder / name).write_text(json.dumps(data, ensure_ascii=False))

    def context(self): return core.read_context(self.root, 0, "demo", 0)

    def launch(self):
        ctx = self.context()
        job_id = core.start(self.root, ctx, ctx["binding"])
        self.job_ids.append(job_id)
        return job_id

    def wait(self, job_id):
        stop = time.monotonic() + 8
        while time.monotonic() < stop:
            record = jobs.get_job(self.root, job_id)
            if record["state"] not in jobs.ACTIVE:
                return record
            time.sleep(0.04)
        self.fail("Worker did not finish within test deadline")

    def tearDown(self):
        self.release.set()
        for job_id in self.job_ids:
            self.wait(job_id)
        self.env.stop(); self.server.shutdown(); self.server.server_close()
        ui.ROOT, ui.RUN_ROOTS = self.original_root, self.original_runs
        self.tmp.cleanup()

    def test_worker_draft_downloads_and_no_mutation(self):
        ctx = self.context()
        self.assertTrue(ctx["eligible"], ctx["block"])
        self.assertEqual(ctx["record_key"], ui.review_key(self.manifest, self.row))
        before = {p: p.read_bytes() for p in [self.root / self.relative, self.folder / "manifest.json",
                  self.folder / "ai_results.json", self.folder / "reviews_ui.json", self.folder / "issue-0000/source.java.txt"]}
        job_id = self.launch(); job = self.wait(job_id)
        self.assertEqual(job["state"], "DRAFT_READY", job.get("error"))
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.requests[0]["model"], core.MODEL)
        self.assertEqual(self.requests[0]["format"], core.SCHEMA)
        response = self.client.get("/runs/0/demo/patch/0")
        self.assertEqual(response.status_code, 200)
        self.assertIn("chưa biên dịch hoặc kiểm thử".encode(), response.data)
        self.assertIn(b"diff-add", response.data)
        for kind in ("patch", "source", "json"):
            r = self.client.get(f"/runs/0/demo/patch/0/download/{job_id}/{kind}")
            self.assertEqual(r.status_code, 200); self.assertIn("attachment", r.headers["Content-Disposition"])
        self.assertEqual(self.launch(), job_id)
        self.assertEqual(self.calls, 1)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        for route in ("/", "/analysis", "/scan", "/runs/0/demo", "/runs/0/demo/priority", "/runs/0/demo/statistics",
                      "/runs/0/demo/report.pdf", "/analysis/jobs/" + job_id):
            self.assertEqual(self.client.get(route).status_code, 200, route)

    def test_current_review_and_source_required(self):
        self.reviews["history"][0]["reviewed_verdict"] = "LIKELY_FP"; self.write()
        ctx = self.context(); self.assertFalse(ctx["eligible"])
        with self.assertRaises(ValueError): core.start(self.root, ctx, ctx["binding"])
        self.reviews["history"][0]["reviewed_verdict"] = "LIKELY_TP"; self.write()
        (self.root / self.relative).write_text(SOURCE + "// working source changed")
        self.assertFalse(self.context()["eligible"])
        (self.root / self.relative).write_text(SOURCE)
        self.row["explanation"] = "Record changed"; self.write()
        self.assertFalse(self.context()["eligible"])
        self.assertEqual(self.calls, 0)

    def test_needs_context_and_truncated_response(self):
        self.proposal.update(status="NEEDS_CONTEXT", updated_source="", missing_context=["Quyền thay đổi symlink và thư mục gốc."])
        job_id = self.launch(); self.assertEqual(self.wait(job_id)["state"], "NEEDS_CONTEXT")
        self.assertEqual(self.client.get(f"/runs/0/demo/patch/0/download/{job_id}/source").status_code, 404)
        self.reviews["history"][0]["revision"] = 2; self.write()
        self.body_override["done_reason"] = "length"
        job_id = self.launch(); job = self.wait(job_id)
        self.assertEqual(job["state"], "FAILED")
        self.assertIn("bị cắt", job["error"])
        self.assertFalse((jobs.job_path(self.root, job_id) / "proposal.json").exists())

    def test_lock_and_review_changed_during_generation(self):
        self.release.clear()
        job_id = self.launch()
        self.assertTrue(self.entered.wait(5))
        with self.assertRaisesRegex(ValueError, "tác vụ"):
            jobs.launch(self.root, {"mode": "check"})
        self.assertEqual(self.launch(), job_id)
        self.reviews["history"][0]["reviewed_verdict"] = "UNKNOWN"; self.write()
        self.release.set()
        job = self.wait(job_id)
        self.assertEqual(job["state"], "FAILED")
        self.assertIn("đã đổi", job["error"])
        self.assertEqual(self.calls, 1)

    def test_stale_download_and_escaped_response(self):
        self.proposal["summary"] = "<script>alert(1)</script>"
        job_id = self.launch(); self.assertEqual(self.wait(job_id)["state"], "DRAFT_READY")
        html = self.client.get("/runs/0/demo/patch/0").data
        self.assertNotIn(b"<script>", html); self.assertIn(b"&lt;script&gt;", html)
        (self.root / self.relative).write_text(SOURCE + "// new version")
        self.assertEqual(self.client.get(f"/runs/0/demo/patch/0/download/{job_id}/source").status_code, 409)
        self.assertIn("không còn khớp".encode(), self.client.get("/runs/0/demo/patch/0").data)

    def test_csrf_stale_binding_and_wrong_job(self):
        base = "/runs/0/demo/patch/0"
        self.client.get(base)
        self.assertEqual(self.client.post(base + "/start", data={"binding": self.context()["binding"]}).status_code, 400)
        with self.client.session_transaction() as session: token = session["csrf"]
        response = self.client.post(base + "/start", data={"csrf": token, "binding": "old"})
        self.assertEqual(response.status_code, 303); self.assertEqual(self.calls, 0)
        response = self.client.post(base + "/start", data={"csrf": token, "binding": self.context()["binding"]})
        job_id = parse_qs(urlsplit(response.headers["Location"]).query)["job"][0]; self.job_ids.append(job_id)
        self.assertEqual(self.wait(job_id)["state"], "DRAFT_READY")
        self.assertEqual(self.client.get(base + "?job=" + "a" * 32).status_code, 404)
        self.assertEqual(self.client.get("/runs/0/demo/patch/99").status_code, 409)

    def test_result_tampering_and_retry(self):
        job_id = self.launch(); self.wait(job_id)
        (jobs.job_path(self.root, job_id) / "proposal.json").write_text("{modified}")
        self.assertEqual(self.client.get(f"/runs/0/demo/patch/0/download/{job_id}/source").status_code, 409)
        new_id = self.launch()
        self.assertNotEqual(new_id, job_id)
        self.assertEqual(self.wait(new_id)["state"], "DRAFT_READY")

    def test_bounds_local_api_and_diff(self):
        ctx = self.context(); req = core.make_request(ctx, core.settings())
        body = {"model": core.MODEL, "done": True, "prompt_eval_count": 1200, "response": json.dumps(self.proposal)}
        for altered in ({**body, "done": False}, {**body, "prompt_eval_count": 8000},
                        {**body, "response": json.dumps({**self.proposal, "updated_source": SOURCE})}):
            with self.assertRaises(ValueError): core.parse_proposal(altered, req, ctx)
        self.assertIn("\\ No newline at end of file", core.unified_diff({**ctx, "source": "before"}, "after"))
        with patch.dict(os.environ, {"OLLAMA_URL": "https://example.com"}):
            with self.assertRaises(ValueError): core.settings()
        (self.folder / "issue-0000/source.java.txt").unlink()
        (self.folder / "issue-0000/source.java.txt").symlink_to(self.root / self.relative)
        self.assertFalse(self.context()["eligible"])


if __name__ == "__main__": unittest.main()
