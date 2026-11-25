from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sql_llm_experiment import plan, validate
from sql_pipeline.evidence.sql_project_paths import case_files, split_batch, stage_snapshot


class SqlProjectPathsTest(unittest.TestCase):
    def test_snapshot_captures_manifest_java_and_refuses_changed_sources(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            text = b"class Api {} // review\n"
            source = root / "Api.java"
            source.write_bytes(text)
            (root / "Unscanned.java").write_text("class Unscanned {}")
            manifest = {"Api.java": sha256(text).hexdigest()}
            files = stage_snapshot(root, manifest, root / "snapshot")
            self.assertEqual(set(files), {"Api.java"})
            self.assertEqual(files["Api.java"]["masked_source"].strip(), "class Api {}")
            source.write_text("class Api { int changed; }")
            with self.assertRaisesRegex(ValueError, "hash differs"):
                stage_snapshot(root, manifest, root / "next")

    def test_projects_add_only_required_files_and_preserve_existing_ids(self):
        index = {name: {"path": name, "kind": "JAVA", "sha256": name, "masked_source": "class Sample {}"}
                 for name in ("Main.java", "Service.java", "Controller.java", "Unused.java")}
        old = {"F0": index["Main.java"], "F1": index["Service.java"]}
        files, ids = case_files(old, index, {"Controller.java"})
        self.assertEqual(ids, {"Main.java": "F0", "Service.java": "F1", "Controller.java": "F2"})
        self.assertEqual(set(files), {"F0", "F1", "F2"})

    def test_batch_demultiplexes_alert_results_and_refuses_missing_cases(self):
        output = "SQL_CASE\t2\nSQL_PATH\tSINK\t1\t1\nSQL_CASE\t3\nSQL_PATH\tSINK\t0\t0"
        self.assertEqual(split_batch(output, {2, 3})[3], "SQL_PATH\tSINK\t0\t0")
        with self.assertRaisesRegex(ValueError, "expected alert batch"):
            split_batch(output, {2, 3, 4})

    def test_new_project_files_use_only_visible_code_as_citation_evidence(self):
        main = {"path": "Repo.java", "kind": "JAVA", "masked_source": "execute(sql);", "sha256": "hash"}
        helper = {"path": "Controller.java", "kind": "JAVA", "path_context_only": True,
                  "masked_source": "unseenCode();\n" + "\n" * 9 + "readInput();\n", "sha256": "helper"}
        trace = {"scope": "verified_java_snapshot", "status": "candidate_paths", "candidate_paths_found": 1,
                 "matched_sources": 1, "source_count": 1, "paths_not_shown": 0, "search_limit_hit": False,
                 "interpretation": "Candidate", "paths": [{
                     "source": {"file_id": "F1", "line": 11, "api_owner": "Input", "api_signature": "readInput()"},
                     "sink": {"file_id": "F0", "line": 1}, "steps": [], "dispatch": [],
                     "omitted_steps": 0, "unlocated_nodes": 0,
                 }]}
        raw = {"issue_id": "a", "component": "fixture:Repo.java", "rule": "rule", "cwe_id": "CWE-89",
               "start_line": 1, "end_line": 1, "source_sha256": "hash", "joern": {},
               "source_context": {"files": {"F0": main, "F1": helper}, "missing_context": []},
               "selected_evidence": {"anchored_paths": trace}}
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            path.write_text(json.dumps(raw))
            row, request = plan(path, path_snippets=True)["a"]
            with self.assertRaisesRegex(ValueError, "requires --path-snippets"):
                plan(path)
        self.assertIn("F1:11 readInput();", request["prompt"])
        self.assertNotIn("unseenCode", request["prompt"])
        answer = {"verdict": "UNKNOWN", "explanation": "Needs context", "citations": [{"file_id": "F1", "line": 11}]}
        self.assertEqual(validate(answer, row), answer)
        with self.assertRaisesRegex(ValueError, "outside provided code"):
            validate({**answer, "citations": [{"file_id": "F1", "line": 1}]}, row)
