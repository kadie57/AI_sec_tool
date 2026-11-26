import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from analyzers.sql_injection.sql_llm_experiment import plan, validate


class SqlPathPresentationTest(unittest.TestCase):
    def plan_case(self, paths, *, selected_evidence=None, verified_sink_note=False, structured_sink_evidence=False):
        row = {
            "alert": {"issue_id": "example", "cwe": "CWE-89", "start_line": 32, "end_line": 32},
            "source": {"file_id": "F0", "kind": "JAVA", "path": "Example.java", "sha256": "snapshot",
                       "lines": [f"statement{line}();" for line in range(1, 45)]},
            "helpers": [{"file_id": "F1", "kind": "JAVA", "path": "Helper.java", "lines": ["return value;"]}],
            "joern_summary": {"flow_count": len(paths)},
            "missing_context": [],
            "selected_evidence": {"paths": paths, **(selected_evidence or {})},
        }
        with TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.jsonl"
            evidence.write_text(json.dumps(row) + "\n", encoding="utf-8")
            visible, request = plan(evidence, path_snippets=True, verified_sink_note=verified_sink_note,
                                    structured_sink_evidence=structured_sink_evidence)["example"]
        return visible, json.loads(request["prompt"])

    def test_renders_ordered_steps_at_original_positions_and_keeps_helper(self):
        path = {"source_line": 10, "intermediate_lines": [23, 17, 23], "sql_argument_line": 33}
        row, prompt = self.plan_case([path])
        selected = prompt["selected_evidence"]
        block, = selected["paths"]
        self.assertEqual(list(block)[:3], ["Source", "Steps", "Sink"])
        self.assertIn("F0:10 statement10();", block["Source"]["code"])
        self.assertEqual(block["Steps"], [f"F0:{line} statement{line}();" for line in (23, 17, 23)])
        self.assertIn("F0:33 statement33();", block["Sink"]["code"])
        self.assertIn("F0:32 statement32();", selected["alert_excerpt"])
        self.assertNotIn("lines", prompt["files"][0])
        self.assertEqual(prompt["files"][1]["lines"], ["return value;"])
        self.assertEqual(row["source"]["lines"][22], "statement23();")

    def test_alert_fallback_preserves_citable_line_and_rejects_hidden_line(self):
        row, prompt = self.plan_case([])
        selected = prompt["selected_evidence"]
        self.assertEqual(selected["paths"], [])
        self.assertIn("F0:32 statement32();", selected["alert_excerpt"])
        assessment = {"verdict": "LIKELY_FP", "explanation": "Example with two references.",
                      "citations": [{"file_id": "F0", "line": 32}, {"file_id": "F1", "line": 1}]}
        self.assertEqual(validate(assessment, row), assessment)
        assessment["citations"][1] = {"file_id": "F0", "line": 1}
        with self.assertRaisesRegex(ValueError, "Citation outside provided code"):
            validate(assessment, row)

    def test_prefers_anchored_paths_and_exposes_candidate_dispatch(self):
        source = {"file_id": "F1", "line": 1, "method": "read", "api_owner": "ServletRequest",
                  "api_signature": "getParameter(String)"}
        sink = {"file_id": "F0", "line": 32, "method": "query"}
        step = {"file_id": "F0", "line": 24, "method": "forward", "node_type": "Call"}
        dispatch = [{"file_id": "F0", "line": 24, "name": "forward", "possible_targets": [
            {"file_id": "F1", "line": 1, "method": "Helper.forward"},
        ]}]
        anchored = {"scope": "verified_java_bundle", "status": "candidate_paths",
                    "source_count": 1, "matched_sources": 1, "candidate_paths_found": 1, "paths_not_shown": 0,
                    "interpretation": "Candidate dataflow", "search_limit_hit": False,
                    "paths": [{"source": source, "steps": [step], "sink": sink, "dispatch": dispatch,
                               "unlocated_nodes": 0, "omitted_steps": 0}]}
        legacy = {"source_line": 10, "intermediate_lines": [], "sql_argument_line": 32}
        row, prompt = self.plan_case([legacy], selected_evidence={"anchored_paths": anchored})
        selected = prompt["selected_evidence"]
        path, = selected["paths"]
        self.assertEqual(path["Source"]["anchor"], "F1:1")
        self.assertEqual(path["Steps"][0]["code"], "F0:24 statement24();")
        self.assertEqual(path["Sink"]["anchor"], "F0:32")
        self.assertEqual(path["possible_dispatch"], dispatch)
        self.assertEqual(selected["anchored_dataflow"]["interpretation"], "Candidate dataflow")
        checked = {"verdict": "LIKELY_TP", "explanation": "Example", "citations": [
            {"file_id": "F0", "line": 32}, {"file_id": "F1", "line": 1},
        ]}
        self.assertEqual(validate(checked, row), checked)

    def value_evidence(self, status, facts, *, proof_column=5):
        argument = {"file_id": "F0", "line": 33}
        return {
            "endpoint_specifications": {"sink_resolution": "one_verified_signature", "sinks": [
                {"file_id": "F0", "line": 32, "column": 5, "role": "sql_text", "argument_index": 1, "argument": argument}
            ]},
            "jdbc_value_evidence": {"status": "evaluated", "scope": "modeled_java_execution_up_to_the_reported_call",
                "arguments": [{"call": {"file_id": "F0", "line": 32, "column": proof_column}, "sql_argument": argument,
                               "status": status, "reason": "bounded_java_evaluation", "evidence": facts}]},
        }

    def test_adds_one_constant_note_to_the_matching_sink(self):
        path = {"source_line": 10, "intermediate_lines": [17, 23], "sql_argument_line": 33}
        facts = [{"file_id": "F0", "line": 17, "role": "switch_case_selected"},
                 {"file_id": "F0", "line": 23, "role": "constant_expression"},
                 {"file_id": "F0", "line": 23, "role": "helper_return"}]
        selected = self.value_evidence("constant_sql_text", facts)
        _, result = self.plan_case([path, path], selected_evidence=selected, verified_sink_note=True)
        _, baseline = self.plan_case([path, path], selected_evidence={"endpoint_specifications": selected["endpoint_specifications"]})
        note = result["selected_evidence"]["paths"][0]["Sink"].pop("verified_value")
        self.assertIn("F0:33 (JDBC call F0:32) is constant", note)
        self.assertIn("F0:17 selected case", note)
        self.assertIn("F0:23 helper return", note)
        self.assertEqual(result, baseline)

    def test_external_input_note_with_helper_reference_and_no_candidate_path(self):
        evidence = self.value_evidence("external_input_contributes", [{"file_id": "F1", "line": 1, "role": "servlet_request_read"}])
        _, result = self.plan_case([], selected_evidence=evidence, verified_sink_note=True)
        selected = result["selected_evidence"]
        self.assertEqual(selected["paths"], [])
        self.assertIn("request data read at F1:1 contributes to the SQL text argument at F0:33", selected["verified_alert_sink"])

    def test_unknown_out_of_range_or_mismatched_proofs_keep_the_control_payload(self):
        path = {"source_line": 10, "intermediate_lines": [], "sql_argument_line": 33}
        for status, line, column in [("unknown", 10, 5), ("constant_sql_text", 45, 5), ("constant_sql_text", 10, 6)]:
            with self.subTest(status=status, line=line, column=column):
                evidence = self.value_evidence(status, [{"file_id": "F0", "line": line, "role": "constant_expression"}],
                                               proof_column=column)
                _, result = self.plan_case([path], selected_evidence=evidence, verified_sink_note=True)
                _, structured = self.plan_case([path], selected_evidence=evidence, structured_sink_evidence=True)
                _, baseline = self.plan_case([path], selected_evidence={"endpoint_specifications": evidence["endpoint_specifications"]})
                self.assertEqual(result, baseline)
                self.assertEqual(structured, baseline)

    def test_structured_proof_exposes_distant_assignments_and_returns_without_joern_path(self):
        facts = [{"file_id": "F0", "line": line, "role": role} for line, role in [
            (5, "constant_expression"), (5, "local_assignment"), (6, "helper_return"),
            (18, "local_definition"), (18, "helper_call"),
        ]]
        evidence = self.value_evidence("constant_sql_text", facts)
        row, prompt = self.plan_case([], selected_evidence=evidence, structured_sink_evidence=True)
        selected = prompt["selected_evidence"]
        self.assertEqual(selected["paths"], [])
        self.assertEqual(selected["supporting_excerpts"], [
            f"F0:{line} statement{line}();" for line in (5, 6, 18)
        ])
        proof = selected["verified_alert_sink"]
        self.assertEqual([fact["line"] for fact in proof["value_to_jdbc"]], [5, 6, 18, 33])
        assessment = {"verdict": "LIKELY_FP", "explanation": "The SQL text is constant.",
                      "citations": [{"file_id": "F0", "line": 32}, {"file_id": "F0", "line": 5}]}
        self.assertEqual(validate(assessment, row), assessment)

    def test_structured_sink_separates_warning_branch_and_ordered_value_chain(self):
        path = {"source_line": 10, "intermediate_lines": [17, 23, 20, 28], "sql_argument_line": 33}
        roles = [(13, "constant_expression"), (14, "switch_selector"), (17, "switch_case_selected"),
                 (23, "constant_expression"), (23, "helper_return"), (20, "helper_call"), (28, "string_concatenation")]
        facts = [{"file_id": "F0", "line": line, "role": role} for line, role in roles]
        evidence = self.value_evidence("constant_sql_text", facts)
        _, formatted = self.plan_case([path], selected_evidence=evidence, structured_sink_evidence=True)
        _, note = self.plan_case([path], selected_evidence=evidence, verified_sink_note=True)
        sink = formatted["selected_evidence"]["paths"][0]["Sink"]
        result = sink["verified_value"]
        self.assertEqual(result["warning_anchor"], {"file_id": "F0", "line": 32, "code": "statement32();"})
        self.assertEqual([item["line"] for item in result["selected_branch"]], [14, 17])
        self.assertEqual([item["line"] for item in result["value_to_jdbc"]], [23, 20, 28, 33])
        self.assertEqual([item["line"] for item in result["constant_context"]], [13])
        self.assertEqual(result["decisive_citation_roles"], {"warning_line": {"file_id": "F0", "line": 32},
            "verified_support_lines": [{"file_id": "F0", "line": 17}, {"file_id": "F0", "line": 23}]})
        sink["verified_value"] = note["selected_evidence"]["paths"][0]["Sink"]["verified_value"]
        self.assertEqual(formatted, note)

    def test_structured_external_input_proof_preserves_helper_coordinates(self):
        evidence = self.value_evidence("external_input_contributes", [{"file_id": "F1", "line": 1, "role": "servlet_request_read"}])
        _, prompt = self.plan_case([], selected_evidence=evidence, structured_sink_evidence=True)
        proof = prompt["selected_evidence"]["verified_alert_sink"]
        self.assertEqual(proof["selected_branch"], [])
        self.assertEqual(proof["value_to_jdbc"][0], {"file_id": "F1", "line": 1, "code": "return value;", "role": "servlet_request_read"})
        self.assertEqual(proof["decisive_citation_roles"]["verified_support_lines"], [{"file_id": "F1", "line": 1}])

    def test_integer_proof_includes_exact_definitions_outside_path_excerpts(self):
        path = {"source_line": 10, "intermediate_lines": [19], "sql_argument_line": 33}
        roles = [(2, "constant_expression"), (19, "integer_comparison"), (19, "conditional_value_selected")]
        evidence = self.value_evidence("constant_sql_text", [{"file_id": "F0", "line": n, "role": role} for n, role in roles])
        visible, prompt = self.plan_case([path], selected_evidence=evidence, structured_sink_evidence=True)
        selected = prompt["selected_evidence"]
        proof = selected["paths"][0]["Sink"]["verified_value"]
        self.assertIn("F0:2 statement2();", selected["supporting_excerpts"])
        self.assertEqual([item["line"] for item in proof["constant_context"]], [2])
        self.assertEqual(visible["source"]["lines"][1], "statement2();")
        self.assertFalse(visible["source"]["lines"][0])
