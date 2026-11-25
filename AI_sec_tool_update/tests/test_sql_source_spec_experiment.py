import unittest

from sql_source_spec_experiment import validate_labels
from sql_pipeline.evidence.sql_source_paths import endpoints


class SqlSourceSpecificationExperimentTest(unittest.TestCase):
    def test_source_classification_cites_an_actual_shown_line(self):
        candidates = {"call-1": {"context": {"call": [{"line": 9, "code": "read()"}], "definition": []}}}
        classification = {"id": "call-1", "label": "external_read", "kind": "console",
                          "citation": {"section": "call", "line": 9}}
        self.assertEqual(validate_labels([classification], candidates), {"call-1": classification})
        without_subtype = {**classification, "kind": None}
        self.assertEqual(validate_labels([without_subtype], candidates), {"call-1": without_subtype})
        with self.assertRaises(ValueError):
            validate_labels([{**classification, "citation": {"section": "definition", "line": 9}}], candidates)

    def test_baseline_servlet_read_takes_precedence_when_proposed_again(self):
        known = {"file_id": "F0", "line": 9, "signature": "getParameter(java.lang.String)",
                 "owner": "javax.servlet.ServletRequest", "role": "servlet_request_read"}
        repeated = {**known, "semantic_status": "qwen_candidate", "input_kind": "request"}
        new = {"file_id": "F1", "line": 4, "signature": "readLine()", "owner": "java.io.BufferedReader",
               "semantic_status": "qwen_candidate", "input_kind": "console"}
        sources, _ = endpoints({"sources": [known], "source_proposals": [repeated, new],
                                "sinks": [], "sink_resolution": "unresolved"})
        self.assertEqual(sources, [{**known, "name": "getParameter"}, {**new, "name": "readLine"}])
