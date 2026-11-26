import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from analyzers.sql_injection.sql_llm_experiment import configuration, plan, read, run


class SqlPromptProfilesTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.input = self.directory / "evidence.jsonl"
        row = {
            "alert": {"issue_id": "example", "cwe": "CWE-89", "start_line": 3, "end_line": 3},
            "source": {"file_id": "F0", "path": "Example.java", "kind": "JAVA", "sha256": "snapshot",
                       "lines": ["String text = makeText();", "", "statement.execute(text);"]},
            "helpers": [],
            "joern_summary": {},
            "missing_context": [],
            "selected_evidence": {"paths": []},
        }
        self.input.write_text(json.dumps(row) + "\n", encoding="utf-8")

    def test_profiles_keep_identical_evidence_and_validation_with_different_output_order(self):
        baseline_row, baseline = plan(self.input, path_snippets=True)["example"]
        current_row, current = plan(self.input, path_snippets=True, prompt_profile="iris-contextual")["example"]

        self.assertEqual(baseline_row, current_row)
        self.assertEqual({k for k in baseline if baseline[k] != current[k]}, {"system", "format"})
        self.assertEqual(baseline["format"]["properties"], current["format"]["properties"])
        self.assertEqual(tuple(current["format"]["properties"]), ("explanation", "citations", "verdict"))
        self.assertEqual(current["format"]["required"], ["explanation", "citations", "verdict"])
        self.assertEqual(configuration()["validation_version"],
                         configuration(prompt_profile="iris-contextual")["validation_version"])

    def test_dry_run_records_the_profile_and_rejects_mismatched_requests(self):
        items = plan(self.input, prompt_profile="iris-contextual")
        output = self.directory / "dry-run"
        with self.assertRaisesRegex(ValueError, "declared prompt profile"):
            run(items, output, timeout=1, dry_run=True)
        self.assertFalse(output.exists())
        run(items, output, timeout=1, dry_run=True, prompt_profile="iris-contextual")
        manifest = read(output / "manifest.json")
        self.assertEqual(manifest["prompt_profile"], "iris-contextual")
        self.assertEqual(manifest["request_version"], 3)
