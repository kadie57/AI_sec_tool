"""Offline regression tests. No live SonarQube, Docker, or model execution."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

PACKAGE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--artifacts", type=Path)
args, rest = parser.parse_known_args()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mapper = types.ModuleType("cwe_mapper")
mapper.MAPPING_VERSION = "test"
mapper.get_cwe_info = lambda rule: {"supported": True, "cwe_id": "CWE-89", "reason": ""}
prompter = types.ModuleType("iris_prompter")
prompter.PROMPT_VERSION = "test"
prompter.unknown_result = lambda reason, kind: {"verdict": "UNKNOWN", "explanation": reason, "error_kind": kind}
prompter.build_advanced_iris_prompt = lambda rule, raw, paths, issue: raw
prompter.ask_ollama_local = lambda *a: None
with patch.dict(sys.modules, cwe_mapper=mapper, iris_prompter=prompter, requests=types.ModuleType("requests")):
    pipeline = load("tested_pipeline", PACKAGE / "payload/master_pipeline.py")
installer = load("tested_installer", PACKAGE / "install.py")
runner = load("tested_recheck", PACKAGE / "payload/recheck_sql_context.py")


class RegressionTests(unittest.TestCase):
    def analyze(self, source, evidence, source_only=True, ai_result=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Example.java").write_text(source, encoding="utf-8")
            output = root / "run"
            output.mkdir()
            model = Mock(return_value=ai_result or {"verdict": "UNKNOWN", "error_kind": None})
            with patch.object(pipeline, "SQL_SIZE_GATE_SOURCE_ONLY", source_only), \
                    patch.object(pipeline, "SQL_NO_FLOW_FALLBACK", True), \
                    patch.object(pipeline, "run_joern_slicing", return_value=evidence), \
                    patch.object(pipeline, "ask_ollama_local", model):
                row = pipeline.analyze_issue({"key": "one", "rule": "sql", "line": 1,
                    "component": "p:Example.java"}, "p", root, output, "unused", 1)
            return row, model.call_count

    def test_unsent_cpg_does_not_block_but_legacy_path_keeps_gate(self):
        ev = {"flow_count": 1, "paths": "x" * 20000}
        before, calls = self.analyze("class Example {}", ev, source_only=False)
        self.assertEqual((before["error_kind"], calls), ("CONTEXT_TOO_LARGE", 0))
        for verdict in ("LIKELY_TP", "LIKELY_FP", "UNKNOWN"):
            row, calls = self.analyze("class Example {}", ev,
                ai_result={"verdict": verdict, "error_kind": None})
            self.assertEqual(calls, 1)
            self.assertEqual(row["verdict"], verdict)
            self.assertFalse(row["context_size_gate"]["is_token_count"])

    def test_missing_or_ambiguous_sink_still_abstains(self):
        for calls, arguments in ((None, None), (0, 0), (2, 2), (1, 0)):
            row, count = self.analyze("class Example {}", {"flow_count": 0, "paths": "",
                "sink_call_count": calls, "sink_argument_count": arguments})
            self.assertEqual((row["error_kind"], count), ("NO_MATCHING_FLOW", 0))

    def test_source_cap_and_downstream_context_errors_remain(self):
        ev = {"flow_count": 1, "paths": "one flow"}
        row, count = self.analyze("x" * 10001, ev)
        self.assertEqual((row["error_kind"], count), ("CONTEXT_TOO_LARGE", 0))
        row, count = self.analyze("class Example {}", ev,
            ai_result={"verdict": "UNKNOWN", "error_kind": "CONTEXT_LIMIT"})
        self.assertEqual((row["verdict"], row["processing_status"], count), ("UNKNOWN", "ABSTAINED", 1))

    def test_existing_unique_no_flow_fallback_unchanged(self):
        row, count = self.analyze("class Example {}", {"flow_count": 0, "paths": "",
            "sink_call_count": 1, "sink_argument_count": 1})
        self.assertEqual((row["analysis_mode"], row["verdict"], count), ("SOURCE_ONLY_NO_FLOW", "UNKNOWN", 1))

    @unittest.skipUnless(args.artifacts, "pass --artifacts to replay the eight saved cases")
    def test_eight_real_saved_inputs_reach_analysis_without_changing_verdicts(self):
        root = args.artifacts
        rows = json.loads((root / "ai_results.json").read_text())
        selected = [r for r in rows if r.get("analysis_route") == "sql" and r.get("error_kind") == "CONTEXT_TOO_LARGE"]
        self.assertEqual(len(selected), 8)
        for row in selected:
            with self.subTest(artifact=row["artifact_dir"]):
                folder = root / row["artifact_dir"]
                source = (folder / "source.java.txt").read_text()
                ev = json.loads((folder / "cpg_evidence.json").read_text())
                before, old_calls = self.analyze(source, ev, source_only=False)
                after, new_calls = self.analyze(source, ev)
                self.assertEqual((before["error_kind"], old_calls), ("CONTEXT_TOO_LARGE", 0))
                self.assertEqual((after["error_kind"], new_calls, after["verdict"]), (None, 1, "UNKNOWN"))

    def test_recheck_selects_processing_failure_not_verdict_and_checks_source(self):
        item = {"issue": {"key": "i", "component": "p:A.java", "line": 2}, "route": "sql", "raw": b"source"}
        row = {"issue_id": "i", "component": "p:A.java", "line": 2, "source_sha256": runner.sha(b"source"),
            "analysis_route": "sql", "error_kind": "CONTEXT_TOO_LARGE", "verdict": "UNKNOWN"}
        self.assertEqual(runner.select_items([row], [item]), [item])
        with self.assertRaises(ValueError):
            runner.select_items([{**row, "source_sha256": "wrong"}], [item])
        with self.assertRaises(ValueError):
            runner.select_items([{**row, "error_kind": None}], [item])

    def test_installer_refuses_changed_backend_before_writes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "master_pipeline.py"
            path.write_text("# local modifications\n")
            with self.assertRaises(ValueError):
                installer.install(root, PACKAGE)
            self.assertEqual(path.read_text(), "# local modifications\n")
            self.assertFalse((root / "backups").exists())


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + rest)
