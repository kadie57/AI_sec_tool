from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prepare_sql_evidence import export_evidence
from sql_pipeline.evidence.sql_source_paths import endpoints, select_paths


class SqlSourcePathsTest(unittest.TestCase):
    def setUp(self):
        self.files = {
            "F0": {"path": "app/Main.java", "kind": "JAVA", "masked_source": "flow();\nquery();\nsqlText"},
            "F1": {"path": "app/Helper.java", "kind": "JAVA", "masked_source": "return request.getParameter(key);"},
            "F2": {"path": "app/Other.java", "kind": "JAVA", "masked_source": "String apply(String value) {"},
        }
        self.read = {"file_id": "F1", "line": 1, "owner": "javax.servlet.ServletRequest",
                     "signature": "getParameter(java.lang.String)"}
        self.sink = {"file_id": "F0", "line": 2, "role": "sql_text", "argument_index": 1,
                     "signature": "executeQuery(java.lang.String)", "argument": {"file_id": "F0", "line": 3}}

    def test_uses_verified_wrapper_return_but_omits_declaration_only(self):
        wrapper = {"role": "helper_returns_servlet_read", "return_evidence": self.read}
        speculative = {"role": "helper_declaration_returns_servlet_read",
                       "return_evidence": {**self.read, "line": 7}}
        sources, sink = endpoints({"sources": [wrapper, speculative],
                                   "sink_resolution": "one_verified_signature", "sinks": [self.sink]})
        self.assertEqual(sources, [{**self.read, "name": "getParameter"}])
        self.assertEqual(sink, self.sink)

    def test_preserves_cross_file_order_and_uses_verified_argument_position(self):
        records = [
            ("SINK", 1, 1), ("SOURCE", 0, 1), ("COUNT", 0, 1),
            ("NODE", 0, 0, "Call", "app/Helper.java", 1, "get", 1, 1),
            ("NODE", 0, 0, "Call", "app/Main.java", 1, "use", 1, 3),
            ("TARGET", 0, 0, "app/Main.java", 1, "apply", "app/Other.java", 1, "Other.apply"),
            ("NODE", 0, 0, "Return", "app/Other.java", 1, "apply", 1, 1),
            ("NODE", 0, 0, "Identifier", "app/Main.java", 1, "use", 1, 3),
            ("NODE", 0, 0, "Expression", "", 0, "", 0, 0),
        ]
        output = "\n".join("\t".join(map(str, ("SQL_PATH", *record))) for record in records)
        result = select_paths(output, self.files, [self.read], self.sink)
        path, = result["paths"]
        self.assertEqual(path["source"]["file_id"], "F1")
        self.assertEqual([(ref["file_id"], ref["line"]) for ref in path["steps"]],
                         [("F0", 1), ("F2", 1), ("F0", 1)])
        self.assertEqual(path["sink"], {"file_id": "F0", "line": 3, "name": "executeQuery"})
        self.assertEqual(path["dispatch"][0]["possible_targets"][0]["file_id"], "F2")
        self.assertEqual(path["unlocated_nodes"], 1)

    def test_refuses_to_start_from_ambiguous_source_or_sink(self):
        for sink_counts, source_count, status in [
            ((1, 1), 2, "no_matched_http_read"),
            ((2, 2), 1, "sink_not_unique_in_cpg"),
        ]:
            with self.subTest(status=status):
                calls, arguments = sink_counts
                output = f"SQL_PATH\tSINK\t{calls}\t{arguments}\nSQL_PATH\tSOURCE\t0\t{source_count}"
                result = select_paths(output, self.files, [self.read], self.sink)
                self.assertEqual(result["status"], status)
                self.assertEqual(result["paths"], [])

    def test_live_stage_requires_immutable_image_id_in_recorded_index(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "result"
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                export_evidence([], {}, output, {}, ("joern:nightly", {}),
                                specification_dependencies=[], joern_source_paths=True)
            self.assertFalse(output.exists())
