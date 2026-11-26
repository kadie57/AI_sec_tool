import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from analyzers.sql_injection.sql_llm_experiment import assess_response, audit_saved_reviews, plan, run
from analyzers.sql_injection.evidence.sql_endpoint_specifications import infer_specifications
from analyzers.sql_injection.evidence.sql_review_consistency import check_review


def constant_query():
    location = {"file_id": "F0", "line": 2}
    call = {**location, "column": 1}
    return {
        "alert": {"issue_id": "test-warning", "component": "Example.java", "rule": "test-rule", "cwe": "CWE-89",
                  "start_line": 2, "end_line": 2},
        "source": {"file_id": "F0", "path": "Example.java", "kind": "JAVA", "sha256": "example-source-hash",
                   "lines": ['String query = "SELECT 1";', "st.execute(query);"]},
        "helpers": [], "joern_summary": {}, "missing_context": [],
        "selected_evidence": {
            "endpoint_specifications": {"sink_resolution": "one_verified_signature",
                                        "sinks": [{**call, "argument": location, "role": "sql_text", "argument_index": 1}]},
            "jdbc_value_evidence": {"status": "evaluated", "scope": "modeled_java_execution_up_to_the_reported_call",
                                    "arguments": [{"call": call, "sql_argument": location, "status": "constant_sql_text",
                                                   "reason": "bounded_java_evaluation",
                                                   "evidence": [{"file_id": "F0", "line": 1, "role": "constant_expression"}]}]},
        },
    }


def completed_response():
    return {"done": True, "done_reason": "stop", "prompt_eval_count": 150,
            "response": json.dumps({"verdict": "LIKELY_TP", "explanation": "Example model verdict.",
                                    "citations": [{"file_id": "F0", "line": line} for line in (1, 2)]})}


class SqlReviewConsistencyTest(unittest.TestCase):
    def test_keeps_model_output_and_cites_a_fixed_value(self):
        response = completed_response()
        result = {"ollama_response": response.copy()}
        assess_response(result, constant_query())
        self.assertEqual(result["ollama_response"], response)
        self.assertEqual(result["assessment"], json.loads(response["response"]))
        review = result["review_consistency"]
        self.assertEqual(review["status"], "REVIEW_REQUIRED")
        self.assertEqual(review["java_evidence"]["references"], [{"file_id": "F0", "line": 1, "role": "constant_expression"}])

    def test_does_not_flag_when_the_jdbc_proof_does_not_match(self):
        for mismatch in ("call_column", "sql_argument", "wrong_call", "multiple_sinks", "missing_role", "blank_source", "budget"):
            with self.subTest(mismatch=mismatch):
                row = constant_query()
                selected = row["selected_evidence"]
                sink, = selected["endpoint_specifications"]["sinks"]
                argument, = selected["jdbc_value_evidence"]["arguments"]
                if mismatch == "call_column":
                    sink["column"] += 1
                elif mismatch == "sql_argument":
                    argument["sql_argument"] = {"file_id": "F0", "line": 1}
                elif mismatch == "wrong_call":
                    row["alert"].update(start_line=3, end_line=3)
                elif mismatch == "multiple_sinks":
                    selected["endpoint_specifications"]["sinks"].append({**sink, "column": sink["column"] + 1})
                elif mismatch == "missing_role":
                    argument["evidence"][0]["role"] = "variable_read"
                elif mismatch == "blank_source":
                    row["source"]["lines"][0] = ""
                else:
                    argument["reason"] = "budget_exhausted"
                self.assertEqual(check_review(row, {"verdict": "LIKELY_TP"})["status"], "NO_CONFLICT_FLAGGED")

    def test_does_not_flag_unknown_or_negative_model_verdict(self):
        for verdict in ("UNKNOWN", "LIKELY_FP"):
            with self.subTest(verdict=verdict):
                self.assertEqual(check_review(constant_query(), {"verdict": verdict})["status"], "NO_CONFLICT_FLAGGED")

    def test_saved_replay_requires_original_request_and_keeps_saved_files(self):
        row = constant_query()
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            evidence, results = folder / "evidence.jsonl", folder / "stored"
            evidence.write_text(json.dumps(row), encoding="utf-8")
            run(plan(evidence), results, timeout=1, dry_run=True)
            manifest = results / "manifest.json"
            metadata = json.loads(manifest.read_text(encoding="utf-8"))
            manifest.write_text(json.dumps({**metadata, "mode": "ollama"}), encoding="utf-8")
            case = results / "case-0001.json"
            saved = json.loads(case.read_text(encoding="utf-8"))
            response = completed_response()
            saved.update(ollama_response=response, assessment=json.loads(response["response"]))
            saved_bytes = json.dumps(saved).encode()
            case.write_bytes(saved_bytes)
            report = audit_saved_reviews(evidence, results)
            self.assertEqual(report["counts"], {"REVIEW_REQUIRED": 1})
            self.assertEqual(case.read_bytes(), saved_bytes)
            row["source"]["lines"][0] = 'String query = "SELECT 2";'
            evidence.write_text(json.dumps(row), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs from the saved request"):
                audit_saved_reviews(evidence, results)

    @unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "A full JDK is required")
    def test_java_probe_on_new_fixed_and_runtime_dependent_queries(self):
        for expression, proof, review in (
            ('"SELECT 1"', "constant_sql_text", "REVIEW_REQUIRED"),
            ('"SELECT 1" + suffix', "unknown", "NO_CONFLICT_FLAGGED"),
        ):
            with self.subTest(expression=expression), TemporaryDirectory() as directory:
                source = ["import java.sql.Statement;", "class Example {",
                          "    void query(Statement stmt, String suffix) throws Exception {",
                          f"        String sql = {expression};", "        stmt.execute(sql);", "    }", "}"]
                path = Path(directory) / "probe.log"
                row = constant_query()
                row["source"]["lines"] = source
                row["alert"].update(start_line=5, end_line=5)
                bundle = {"files": {"F0": {"path": "Example.java", "kind": "JAVA", "masked_source": "\n".join(source)}}}
                specs = infer_specifications(SimpleNamespace(start=5, end=5), bundle, {}, [], path, value_evidence=True)
                values = specs.pop("jdbc_value_evidence")
                self.assertEqual(values["arguments"][0]["status"], proof)
                row["selected_evidence"] = {"endpoint_specifications": specs, "jdbc_value_evidence": values}
                self.assertEqual(check_review(row, {"verdict": "LIKELY_TP"})["status"], review)
