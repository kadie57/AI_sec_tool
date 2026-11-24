from pathlib import Path
from types import SimpleNamespace
import unittest

from prepare_sql_evidence import prepare_inputs, read_recorded_joern
from sql_pipeline.evidence.joern_sql import path_locations
from sql_pipeline.evidence.source_text import mask_java
from sql_pipeline.evidence.sql_evidence_selection import select_evidence


def bundle(path, source):
    return {"files": {"F0": {"path": path.as_posix(), "masked_source": mask_java(source)}}}


class SqlEvidenceSelectionTest(unittest.TestCase):
    def test_recorded_paths_resolve_to_snapshot_and_keep_branch_context(self):
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "sql8"
        inputs, _ = prepare_inputs(fixture, fixture / "sources", set())
        _, flows = read_recorded_joern(fixture / "joern", inputs)
        self.assertEqual(len(inputs), 8)
        for item in inputs:
            with self.subTest(component=item.relative.name):
                _, flow = flows[item.issue["key"]]
                source = item.source.decode("utf-8")
                context = bundle(item.relative, source)
                selected = select_evidence(item, context, flow)
                locations = {node["line"] for node in selected["locations"]}
                self.assertEqual(selected["path_status"], "selected")
                self.assertEqual(selected["sink_status"], "one_sql_argument_in_alert_range")
                self.assertTrue(all(source.splitlines()[line - 1].strip() for line in locations))
                for path in selected["paths"]:
                    self.assertLessEqual(len(path["intermediate_lines"]), 10)
                    self.assertTrue({path["source_line"], path["sql_argument_line"],
                                     *path["intermediate_lines"]} <= locations)
                if item.relative.name == "BenchmarkTest02093.java":
                    self.assertIn(77, {entry["line"] for entry in selected["nearby_syntax"]})
                    self.assertIn(81, {entry["line"] for entry in selected["nearby_syntax"]})
                    self.assertIn((64, 74), selected["endpoint_context"])

    def test_no_flow_distinguishes_missing_call_and_found_argument(self):
        item = SimpleNamespace(relative=Path("Example.java"), start=2, end=2)
        context = bundle(item.relative, 'if (enabled) {\n  stmt.execute("SELECT 1");\n}')
        flow = {"scope": "single_file", "flow_count": 0, "paths": ""}
        for count, status in [(0, "call_not_located_in_alert_range"),
                              (1, "one_sql_argument_in_alert_range")]:
            with self.subTest(status=status):
                selected = select_evidence(item, context, {**flow, "sink_call_count": count,
                                                           "sink_argument_count": count})
                self.assertEqual(selected["sink_status"], status)
                self.assertEqual(selected["path_status"], "no_candidate_flow")
                self.assertEqual(selected["paths"], [])
                self.assertEqual(selected["nearby_syntax"][0]["line"], 1)

    def test_malformed_table_preserves_warning_context(self):
        item = SimpleNamespace(relative=Path("Example.java"), start=1, end=1)
        context = bundle(item.relative, 'stmt.execute("SELECT 1");\n')
        flow = {"scope": "single_file", "flow_count": 1, "paths": "unexpected output",
                "sink_call_count": 1, "sink_argument_count": 1}
        with self.assertRaises(ValueError):
            path_locations(flow)
        selected = select_evidence(item, context, flow)
        self.assertEqual(selected["path_status"], "path_coordinates_unavailable")
        self.assertEqual(selected["alert_context"], [1, 1])
        self.assertEqual(selected["paths"], [])
