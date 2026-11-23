"""Regression checks for the merge guard; no real inference is performed."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import sql_source_audit_v4 as audit
import remerge_sql_sources as replay

ROOT = Path(replay.__file__).resolve().parent
PREVIOUS = ROOT / replay.DEFAULT


class MergeGuardTests(unittest.TestCase):
    def test_only_simple_origin_questions_are_eligible(self):
        for text in ("nguồn của tham số `param`", "Chưa thấy nguồn của value.", "source of variable requestValue"):
            self.assertTrue(audit.source_only_legacy_gap(text), text)
        for text in ("Nội dung của hàm `doSomething`", "Chi tiết về cách thức xử lý của hàm `doSomething()` và các lớp hỗ trợ khác như `ThingInterface` và `ThingFactory`.",
                     "nguồn của tham số param và nội dung helper", "Cần kiểm tra cơ chế bảo vệ.",
                     "Chưa rõ caller hoặc biến đổi đầu vào.", "source of value after transformation"):
            self.assertFalse(audit.source_only_legacy_gap(text), text)

    def test_actual_eight_remerged_without_network(self):
        with patch.object(audit.core.requests, "get", side_effect=AssertionError("network forbidden")), \
                patch.object(audit.core.requests, "post", side_effect=AssertionError("network forbidden")):
            plan, provenance = replay.prepare(ROOT, PREVIOUS)
            rows = replay.recompute(plan)
        self.assertEqual(provenance["new_model_calls"], 0)
        self.assertEqual(len(rows), 8)
        changes = [r for r in rows if r["verdict"] != r["previous_final_verdict"]]
        self.assertEqual(len(changes), 1)
        self.assertTrue(changes[0]["component"].endswith('BenchmarkTest02186.java'))
        self.assertEqual(changes[0]["verdict"], "UNKNOWN")
        self.assertEqual(changes[0]["ai_verdict"], "LIKELY_TP")
        resolution = changes[0]["gap_resolution"][0]
        self.assertTrue(resolution["model_reported_resolved"])
        self.assertFalse(resolution["resolved"])
        self.assertEqual(resolution["merge_disposition"], "RETAINED")
        self.assertEqual(sum(bool(r["error_kind"]) for r in rows), 2)
        self.assertEqual(next(r["verdict"] for r in rows if r["component"].endswith('BenchmarkTest00999.java')), 'LIKELY_FP')

    def test_context_question_preserved_even_if_model_claims_source_resolved(self):
        plan, _ = replay.prepare(ROOT, PREVIOUS)
        item = next(p for p in plan if p["row"]["component"].endswith('BenchmarkTest02186.java'))
        gaps = item["stage"]["model_assessment"]["missing_context"]
        before = copy.deepcopy(item["record"])
        remaining, _ = audit.reconciled_gaps(item["record"], item["source"], gaps)
        self.assertEqual(remaining, gaps)
        self.assertEqual(before, item["record"])

    def test_blank_reference_reports_exact_line_for_repair(self):
        plan, _ = replay.prepare(ROOT, PREVIOUS)
        for item in plan:
            if item["row"]["component"].endswith(('BenchmarkTest02088.java','BenchmarkTest02093.java')):
                bad = item["record"]["attempts"][-1]["facts_full"]
                gaps = item["stage"]["model_assessment"]["missing_context"]
                with self.assertRaisesRegex(ValueError, "Dòng 45"):
                    audit.check(bad, item["source"], gaps, item["row"]["line"])

    def test_guard_does_not_claim_reference_semantics(self):
        plan, _ = replay.prepare(ROOT, PREVIOUS)
        item = next(p for p in plan if p["row"]["component"].endswith('BenchmarkTest01311.java'))
        # The nonblank method declaration at line 33 still passes structural
        # validation. This known limitation is reported, not hidden by the test.
        self.assertIn("void doGet", item["source"].splitlines()[32])
        full = {**item["record"]["facts"], "gap_reviews": item["record"]["gap_reviews"]}
        self.assertEqual(audit.check(full, item["source"], [], item["row"]["line"]), 'LINES_RESOLVED_REVIEW_REQUIRED')


if __name__ == "__main__":
    unittest.main(verbosity=2)
