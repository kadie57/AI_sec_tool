"""Offline regression tests. Run: python3 -m unittest -v test_pipeline.py

HTTP, Docker, SonarScanner, javac and Joern are mocked. This does not validate
Joern Scala syntax or vulnerability-classification accuracy.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import requests
import cwe_mapper as mapper
import iris_prompter as llm
import master_pipeline as pipeline


def assessment(verdict="LIKELY_TP", lines=None, missing=None):
    return {"verdict": verdict, "explanation": "Có bằng chứng tại vị trí được dẫn.",
            "evidence_lines": [2] if lines is None else lines,
            "missing_context": [] if missing is None else missing}


class MappingTests(unittest.TestCase):
    def test_deprecated_api_is_not_command_injection(self):
        result = mapper.get_cwe_info("java:S1874")
        self.assertIsNone(result["cwe_id"])
        self.assertFalse(result["supported"])

    def test_unknown_security_rule_not_called_code_smell(self):
        result = mapper.get_cwe_info("plugin:NEW_SECURITY_RULE")
        self.assertEqual(result["name"], "Unmapped rule")
        self.assertFalse(result["supported"])

    def test_findsecbugs_jdbc_is_supported(self):
        self.assertTrue(mapper.get_cwe_info("findbugs:SQL_INJECTION_JDBC")["supported"])


class AssessmentTests(unittest.TestCase):
    def test_both_valid_predictions_preserved(self):
        for v in ("LIKELY_TP", "LIKELY_FP"):
            self.assertEqual(llm.validate_assessment(assessment(v), 10)["verdict"], v)

    def test_error_dict_never_becomes_false_positive(self):
        self.assertEqual(llm.validate_assessment({"error": "connection failed"}, 10)["verdict"], "UNKNOWN")

    def test_invalid_types_and_lines_become_unknown(self):
        for data in [None, [], {"is_vulnerable": "false"}, assessment(lines=[True]),
                     assessment(lines=[0]), assessment(lines=[999]),
                     assessment(lines=["2"]), assessment(verdict=True)]:
            with self.subTest(data=data):
                self.assertEqual(llm.validate_assessment(data, 10)["verdict"], "UNKNOWN")

    def test_decisive_verdict_requires_evidence_and_no_missing_context(self):
        for data in [assessment(lines=[]), assessment("LIKELY_FP", missing=["Chưa có caller"])]:
            self.assertEqual(llm.validate_assessment(data, 10)["verdict"], "UNKNOWN")

    def test_unknown_is_permitted_without_evidence(self):
        self.assertEqual(llm.validate_assessment(assessment("UNKNOWN", [], ["Thiếu caller"]), 10)["verdict"], "UNKNOWN")

    @patch("iris_prompter.requests.post")
    def test_http_and_timeouts_never_become_false_positive(self, post):
        for error in [requests.Timeout(), requests.ConnectionError(), requests.HTTPError()]:
            post.side_effect = error
            self.assertEqual(llm.ask_ollama_local("test", 10)["verdict"], "UNKNOWN")

    @patch("iris_prompter.requests.post")
    def test_malformed_and_truncated_output(self, post):
        for body in [{"done": True, "response": "{broken"},
                     {"done": True, "response": '{"error":"oops"}'},
                     {"done": False, "response": json.dumps(assessment())},
                     {"done": True, "done_reason": "length", "response": json.dumps(assessment())},
                     {"done": True, "error": "model unavailable", "response": ""}]:
            post.return_value = Mock(json=Mock(return_value=body))
            self.assertEqual(llm.ask_ollama_local("test", 10)["verdict"], "UNKNOWN")

    @patch("iris_prompter.requests.post")
    def test_valid_response_and_reproducible_request(self, post):
        post.return_value = Mock(json=Mock(return_value={"done": True, "response": json.dumps(assessment("LIKELY_FP")), "eval_count": 50}))
        result = llm.ask_ollama_local("test", 10)
        self.assertEqual(result["verdict"], "LIKELY_FP")
        self.assertEqual(result["ollama_response"]["eval_count"], 50)
        sent = post.call_args.kwargs
        self.assertEqual(sent["json"]["format"], llm.OUTPUT_SCHEMA)
        self.assertIn("timeout", sent)


class SonarTests(unittest.TestCase):
    def test_pagination_collects_all_issues(self):
        with tempfile.TemporaryDirectory() as temp:
            sonar = pipeline.SonarClient("http://localhost:9000", "test")
            sonar.get = Mock(side_effect=[
                {"paging": {"total": 2}, "issues": [{"key": "a"}]},
                {"paging": {"total": 2}, "issues": [{"key": "b"}]},
            ])
            result = sonar.fetch_issues("project", Path(temp))
            self.assertEqual([i["key"] for i in result], ["a", "b"])
            self.assertEqual(sonar.get.call_args_list[1].args[1]["p"], 2)

    def test_empty_results_are_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            sonar = pipeline.SonarClient("http://localhost:9000", "test")
            sonar.get = Mock(return_value={"paging": {"total": 0}, "issues": []})
            self.assertEqual(sonar.fetch_issues("project", Path(temp)), [])

    def test_incomplete_page_is_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            sonar = pipeline.SonarClient("http://localhost:9000", "test")
            sonar.get = Mock(return_value={"paging": {"total": 2}, "issues": []})
            with self.assertRaises(RuntimeError):
                sonar.fetch_issues("project", Path(temp))

    def test_duplicate_pages_are_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            sonar = pipeline.SonarClient("http://localhost:9000", "test")
            sonar.get = Mock(return_value={"paging": {"total": 2}, "issues": [{"key": "same"}]})
            with self.assertRaises(RuntimeError):
                sonar.fetch_issues("project", Path(temp))

    @patch("master_pipeline.time.sleep")
    def test_background_task_is_polled_until_success(self, sleep):
        sonar = pipeline.SonarClient("http://localhost:9000", "test")
        sonar.get = Mock(side_effect=[{"task": {"status": "PENDING"}}, {"task": {"status": "SUCCESS", "analysisId": "a"}}])
        self.assertEqual(sonar.wait_for_analysis("t")["analysisId"], "a")
        sleep.assert_called_once()

    def test_failed_background_task_stops_pipeline(self):
        sonar = pipeline.SonarClient("http://localhost:9000", "test")
        sonar.get = Mock(return_value={"task": {"status": "FAILED"}})
        with self.assertRaises(RuntimeError):
            sonar.wait_for_analysis("t")


class EvidenceTests(unittest.TestCase):
    def test_logs_are_not_cpg_evidence(self):
        with self.assertRaises(ValueError):
            pipeline.parse_joern_output("[INFO] Joern started successfully")

    def test_zero_flow_is_recognized(self):
        result = pipeline.parse_joern_output("CPG_RESULT_BEGIN\nFLOW_COUNT=0\n\nCPG_RESULT_END\n")
        self.assertEqual(result["flow_count"], 0)

    def test_source_path_preserves_colon_in_project_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Example.java").write_text("class Example {}")
            self.assertEqual(pipeline.resolve_issue_path({"component": "org:project:Example.java"}, "org:project", root), root / "Example.java")

    def test_paths_outside_project_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                pipeline.resolve_issue_path({"component": "project:../outside.java"}, "project", Path(temp))

    @patch("master_pipeline.ask_ollama_local")
    @patch("master_pipeline.run_joern_slicing", return_value={"flow_count": 0, "paths": ""})
    def test_zero_flow_does_not_call_llm(self, joern, ask):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Example.java").write_text("class Example {}")
            issue = {"key": "a", "rule": "java:S3649", "component": "project:Example.java", "line": 1}
            result = pipeline.analyze_issue(issue, "project", root, root, "image", 1)
            self.assertEqual(result["verdict"], "UNKNOWN")
            self.assertEqual(result["error_kind"], "NO_MATCHING_FLOW")
            ask.assert_not_called()

    @patch("master_pipeline.run_joern_slicing")
    def test_unsupported_rule_is_retained_not_silently_dropped(self, joern):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = pipeline.analyze_issue({"key": "a", "rule": "new:rule"}, "p", root, root, "image", 1)
            self.assertEqual(result["processing_status"], "SKIPPED")
            self.assertEqual(result["verdict"], "UNKNOWN")
            joern.assert_not_called()

    @patch("master_pipeline.subprocess.run")
    def test_compile_failure_is_not_reported_as_success(self, run):
        run.return_value = subprocess.CompletedProcess(["javac"], 1, "", "compile failed")
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RuntimeError):
                pipeline.run_command(["javac"], Path(temp) / "javac.log", 1)

    @patch("master_pipeline.run_command", side_effect=RuntimeError("compile failed"))
    @patch.dict(os.environ, {"SONAR_TOKEN": "test-secret"})
    @patch("sys.argv", ["master_pipeline.py", "--collect-only"])
    def test_main_stops_after_compilation_failure(self, command):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Clean_Code").mkdir()
            (root / "Clean_Code" / "Example.java").write_text("bad java")
            with patch("master_pipeline.Path.cwd", return_value=root):
                self.assertEqual(pipeline.main(), 1)
            self.assertEqual(command.call_count, 1)
            manifest = json.loads(next((root / "runs").glob("*/manifest.json")).read_text())
            self.assertEqual(manifest["state"], "FAILED")
            self.assertNotIn("test-secret", json.dumps(manifest))


if __name__ == "__main__":
    unittest.main()
