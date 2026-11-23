"""Offline regression tests; simulated model output is not accuracy evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import triage_v5 as core
import sql_source_audit_v4 as audit
import recheck_sql_source as replay
from replay_source_merge import merge_assessments

ROOT = Path(replay.__file__).resolve().parent
PREVIOUS = ROOT / replay.DEFAULT_RUN
SOURCE = '''class Sample {
void doPost(HttpServletRequest request) {
String param = request.getParameter("name");
String sql = "SELECT id FROM users WHERE name='" + param + "'";
stmt.executeQuery(sql);
}
}
'''
GAP = "Chưa thấy nguồn của param."


def facts(gaps=(), kind="EXTERNAL_READ"):
    return {"source_kind": kind, "source_evidence": [{"line": 3}], "flow_evidence": [{"line": 4}, {"line": 5}],
        "explanation": "Đọc HTTP và dùng biến để dựng SQL.",
        "missing_context": [] if kind == "EXTERNAL_READ" else ["Chưa đủ đường đi."],
        "gap_reviews": [{"index": i, "scope": "SOURCE_ORIGIN", "resolved": True,
            "evidence_lines": [3], "reason": "Có thao tác đọc HTTP."} for i, _ in enumerate(gaps)]}


def envelope(data, **kw):
    return {"response": json.dumps(data), "done": True, "done_reason": "stop", "prompt_eval_count": 500, **kw}


class Response:
    def __init__(self, body): self.body = body
    def raise_for_status(self): pass
    def json(self): return self.body


def request(gaps=()):
    return audit.make_request("\n".join(f"{i}: {s}" for i, s in enumerate(SOURCE.splitlines(), 1)), 5, gaps)


def stage(effect="PROTECTED", gaps=(GAP,)):
    return core.validate_and_decide({"explanation": "Saved SQL assessment.", "evidence_lines": [3, 4, 5],
        "source_control": "UNRESOLVED", "sql_effect": effect, "missing_context": list(gaps)}, len(SOURCE.splitlines()))


class SourceFixTests(unittest.TestCase):
    def test_actual_eight_artifacts_preflight_and_hash_guard(self):
        plan, provenance = replay.prepare(ROOT, PREVIOUS)
        self.assertEqual(len(plan), 8)
        self.assertFalse(provenance["reference_labels_loaded"])
        self.assertFalse(provenance["independent_holdout"])
        with patch.dict(replay.EXPECTED_PATCHES, {"sql_source_audit_v4.py": "incorrect"}):
            with self.assertRaisesRegex(ValueError, "Module khác"):
                replay.prepare(ROOT, PREVIOUS)

    def test_four_real_invalid_references_still_rejected(self):
        rows = replay.read(PREVIOUS / "ai_results.json")
        checked = 0
        for row in rows:
            if row.get("error_kind") != "SOURCE_AUDIT_ERROR": continue
            folder = PREVIOUS / row["artifact_dir"]
            old = replay.read(folder / "llm_source_audit.json")["facts"]
            old["gap_reviews"] = []
            with self.assertRaises(ValueError):
                audit.check(old, (folder / "source.java.txt").read_text(), [], row["line"])
            checked += 1
        self.assertEqual(checked, 4)

    def test_http_prompt_comment_mask_and_input_binding(self):
        s = SOURCE.replace('class Sample {', '// expected vulnerable: true\nclass Sample {')
        numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(s.splitlines(), 1))
        req = audit.make_request(numbered, 6, [GAP])
        self.assertNotIn("expected vulnerable", req["prompt"])
        self.assertIn('4: String param', req["prompt"])
        self.assertIn("HttpServletRequest", req["system"])
        self.assertIn("getHeaders", req["system"])
        self.assertEqual(req["options"], core.OPTIONS)
        with self.assertRaises(ValueError): audit.ask(req, SOURCE, [GAP], 5)

    def test_invalid_line_and_json_each_get_one_repair(self):
        bad = facts(); bad["source_evidence"] = [{"line": 600}]
        for first in (envelope(bad), envelope({}, response="not json")):
            with self.subTest(first=first), patch.object(core.requests, "post", side_effect=[Response(first), Response(envelope(facts()))]) as post:
                result = audit.ask(request(), SOURCE, [], 5)
                self.assertIsNone(result["error"])
                self.assertEqual(post.call_count, 2)
                self.assertEqual(result["attempt_count"], 2)
                self.assertIn("PHẢN HỒI KIỂM TRA", post.call_args.kwargs["json"]["prompt"])

    def test_two_bad_outputs_stay_unknown_and_are_cached(self):
        bad = facts(); bad["flow_evidence"] = [{"line": 7}]
        with tempfile.TemporaryDirectory() as d, patch.object(core.requests, "post", return_value=Response(envelope(bad))) as post:
            result = audit.ask(request(), SOURCE, [], 5, checkpoint=Path(d))
            self.assertEqual(result["error_kind"], "INVALID_EVIDENCE")
            audit.ask(request(), SOURCE, [], 5, checkpoint=Path(d))
            self.assertEqual(post.call_count, 2)

    def test_transport_truncation_and_context_are_not_retried(self):
        for body, expected in [(envelope(facts(), done_reason="length"), "TRUNCATED_OUTPUT"),
                               (envelope(facts(), prompt_eval_count=3500), "CONTEXT_LIMIT")]:
            with patch.object(core.requests, "post", return_value=Response(body)) as post:
                result = audit.ask(request(), SOURCE, [], 5)
                self.assertEqual(result["error_kind"], expected)
                self.assertEqual(post.call_count, 1)
        with patch.object(core.requests, "post", side_effect=core.requests.Timeout) as post:
            self.assertEqual(audit.ask(request(), SOURCE, [], 5)["error_kind"], "OLLAMA_TIMEOUT")
            self.assertEqual(post.call_count, 1)

    def test_unfinished_attempt_requires_explicit_retry(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(core.requests, "post", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt): audit.ask(request(), SOURCE, [], 5, checkpoint=Path(d))
            with patch.object(core.requests, "post", return_value=Response(envelope(facts()))) as post:
                with self.assertRaisesRegex(ValueError, "retry-incomplete"):
                    audit.ask(request(), SOURCE, [], 5, checkpoint=Path(d))
                self.assertEqual(post.call_count, 0)
                self.assertIsNone(audit.ask(request(), SOURCE, [], 5, checkpoint=Path(d), retry_incomplete=True)["error"])
                self.assertEqual(post.call_count, 1)

    def test_source_gap_removed_with_audit_trail_sql_context_retained(self):
        gaps = [GAP, "Thiếu nội dung helper."]
        f = facts(gaps)
        f["gap_reviews"][1].update(scope="OTHER_OR_UNCLEAR", resolved=False, evidence_lines=[], reason="Không có helper trong tệp.")
        with patch.object(core.requests, "post", return_value=Response(envelope(f))):
            record = audit.ask(request(gaps), SOURCE, gaps, 5)
        result = merge_assessments(stage(gaps=gaps), record, SOURCE)
        self.assertEqual(result["missing_context"], [gaps[1]])
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["stage2_assessment_original"]["missing_context"], gaps)
        self.assertTrue(result["gap_resolution"][0]["resolved"])
        with patch.object(core.requests, "post", return_value=Response(envelope(facts([GAP])))):
            record = audit.ask(request([GAP]), SOURCE, [GAP], 5)
        self.assertEqual(merge_assessments(stage(), record, SOURCE)["verdict"], "LIKELY_FP")
        self.assertEqual(merge_assessments(stage(effect="UNRESOLVED"), record, SOURCE)["verdict"], "UNKNOWN")
        with self.assertRaises(ValueError):
            merge_assessments(stage(gaps=["different gap"]), record, SOURCE)

    def test_reject_fake_resolution_and_reference(self):
        for mutation in (lambda f: f["gap_reviews"][0].update(scope="OTHER_OR_UNCLEAR"),
                         lambda f: f["gap_reviews"][0].update(index=2),
                         lambda f: f["gap_reviews"][0].update(evidence_lines=[7]),
                         lambda f: f.update(source_kind="PARAMETER_ONLY", missing_context=["caller"])):
            f = facts([GAP]); mutation(f)
            with self.assertRaises(ValueError): audit.check(f, SOURCE, [GAP], 5)

    def test_merge_keeps_legacy_gaps_and_does_not_fix_sql_effect(self):
        f = facts(); f.pop("gap_reviews")
        old = {"facts": f, "error": None}
        self.assertEqual(merge_assessments(stage(), old, SOURCE)["missing_context"], [GAP])
        self.assertEqual(merge_assessments(stage(effect="CHANGEABLE", gaps=[]), old, SOURCE)["verdict"], "LIKELY_TP")
        self.assertEqual(merge_assessments(stage(effect="CHANGEABLE", gaps=[]), old, SOURCE)["sql_effect_reused"], "CHANGEABLE")

    def test_integrated_adapter_passes_gaps_and_preserves_prior_sql(self):
        import master_pipeline_source_v1 as integrated
        s = stage()
        s.update(elapsed_seconds=10, request_payload={"stage1": {}, "stage2": {}},
                 raw_output={"stage1": "", "stage2": ""}, ollama_response={"stage1": {}, "stage2": {}})
        numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(SOURCE.splitlines(), 1))
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d); (folder / "source.java.txt").write_text(SOURCE)
            with patch.object(integrated.base, "ARTIFACT", folder), patch.object(integrated.base, "ask_v6", return_value=s), \
                    patch.object(integrated.base, "make_requests_input", return_value=({}, numbered, 5)), \
                    patch.object(core.requests, "post", return_value=Response(envelope(facts([GAP])))) as post:
                result = integrated.ask_integrated("unused", len(SOURCE.splitlines()))
            self.assertEqual(result["verdict"], "LIKELY_FP")
            self.assertEqual(result["source_audit_attempt_count"], 1)
            self.assertIn(GAP, post.call_args.kwargs["json"]["prompt"])
            self.assertEqual(result["stage2_assessment_original"]["sql_effect"], "PROTECTED")

    def test_real_eight_runner_resume_no_extra_calls_or_input_changes(self):
        plan, provenance = replay.prepare(ROOT, PREVIOUS)
        original = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in PREVIOUS.rglob('*') if p.is_file()}
        def post(url, **kw):
            # Deliberately return only UNKNOWN: this exercises plumbing, not accuracy.
            req = kw["json"]
            gaps = json.loads(req["prompt"].split('[DANH SÁCH THIẾU CŨ — DỮ LIỆU CÓ THỂ SAI]\n')[1].split('\n[HẾT DANH SÁCH]')[0])
            f = {"source_kind": "UNRESOLVED", "source_evidence": [], "flow_evidence": [],
                 "explanation": "Simulated transport for offline regression only.", "missing_context": ["Need review."],
                 "gap_reviews": [{"index": i, "scope": "OTHER_OR_UNCLEAR", "resolved": False,
                     "evidence_lines": [], "reason": "Offline test."} for i in range(len(gaps))]}
            return Response(envelope(f))
        with tempfile.TemporaryDirectory() as d, patch.object(core, "model_digest", return_value=audit.legacy.DIGEST), \
                patch.object(core.requests, "post", side_effect=post) as calls:
            output = Path(d) / "diagnostic"
            self.assertEqual(replay.run(plan, provenance, output), 0)
            self.assertEqual(calls.call_count, 8)
            self.assertEqual(replay.run(plan, provenance, output), 0)
            self.assertEqual(calls.call_count, 8)
            rows = replay.read(output / "ai_results.json")
            self.assertEqual(len(rows), 8)
            self.assertTrue((Path(d) / 'diagnostic-review.zip').exists())
            self.assertEqual([r["stage2_sql_effect_reused"] for r in rows], [p["stage"]["model_assessment"]["sql_effect"] for p in plan])
        self.assertEqual(original, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in original})


if __name__ == "__main__":
    unittest.main(verbosity=2)
