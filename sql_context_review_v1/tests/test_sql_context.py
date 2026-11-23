"""Offline invariants; mock model replies are NOT accuracy measurements.

Run from AI_sec_tool:
python3 -m unittest discover -s sql_context_review_v1/tests -v
"""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sql_context_bundle_v1 as context
import sql_context_triage_v1 as triage

MAIN = '''package demo;
public class Entry {
 public void go(Request request) {
  String value = request.getParameter("name");
  String sql = "SELECT id FROM users WHERE name='" + value + "'";
  statement.execute(sql);
 }
}
'''


def bundle(source=MAIN):
    return {"version": context.VERSION, "commit": "a" * 40, "missing_context": [], "links": [],
        "files": {"F0": {"file_id": "F0", "path": "src/main/java/demo/Entry.java", "kind": "JAVA",
                  "source": source, "masked_source": context.mask_java(source), "sha256": context.sha(source.encode())}}}


def facts(stage, unresolved=False):
    if stage == "source":
        return {"source_kind": "UNRESOLVED" if unresolved else "EXTERNAL_READ",
            "explanation": "Synthetic test response.", "source_evidence": [] if unresolved else ["F0:4"],
            "flow_evidence": ["F0:5", "F0:6"], "missing_context": ["Synthetic gap."] if unresolved else []}
    return {"sql_effect": "UNRESOLVED" if unresolved else "CHANGEABLE", "explanation": "Synthetic SQL response.",
            "evidence": ["F0:5", "F0:6"], "missing_context": ["Synthetic gap."] if unresolved else []}


def saved(f):
    return {"facts": f, "error_kind": None}


class EvidenceAndMerge(unittest.TestCase):
    def test_blank_comment_and_braces_are_not_references(self):
        b = bundle(MAIN + '\n// expected label DO_NOT_SEND\n}\n')
        refs = context.references(b)
        self.assertNotIn("F0:9", refs)
        self.assertNotIn("F0:10", refs)
        self.assertNotIn("F0:11", refs)
        self.assertNotIn("DO_NOT_SEND", context.render(b))

    def test_wrong_file_line_and_missing_sink_rejected(self):
        for wrong in ("F5:4", "F0:999", "F0:7"):
            f = facts("source"); f["source_evidence"] = [wrong]
            with self.assertRaises(ValueError):
                triage.validate(f, "source", bundle(), 6)
        f = facts("sql"); f["evidence"] = ["F0:4", "F0:5"]
        with self.assertRaises(ValueError):
            triage.validate(f, "sql", bundle(), 6)

    def test_method_header_is_not_an_external_read(self):
        f = facts("source"); f["source_evidence"] = ["F0:3", "F0:4"]
        with self.assertRaisesRegex(ValueError, "Chữ ký"):
            triage.validate(f, "source", bundle(), 6)

    def test_api_name_in_literal_is_not_an_external_read(self):
        b = bundle(MAIN.replace('request.getParameter("name")', '\"request.getParameter(x)\"'))
        with self.assertRaisesRegex(ValueError, "thao tác đọc"):
            triage.validate(facts("source"), "source", b, 6)

    def test_param_only_can_cite_method_header(self):
        f = facts("source"); f.update(source_kind="PARAMETER_ONLY", source_evidence=["F0:3"], missing_context=["Caller"])
        triage.validate(f, "source", bundle(), 6)

    def test_unknown_can_leave_origin_empty_without_inventing_evidence(self):
        triage.validate(facts("source", True), "source", bundle(), 6)

    def test_resolved_state_with_gaps_rejected(self):
        for stage in ("source", "sql"):
            f = facts(stage); f["missing_context"] = ["unknown helper"]
            with self.assertRaises(ValueError):
                triage.validate(f, stage, bundle(), 6)

    def test_policy_external_changeable(self):
        r = triage.combine(saved(facts("source")), saved(facts("sql")), bundle(), 6)
        self.assertEqual(r["verdict"], "LIKELY_TP")

    def test_policy_constant_protected_and_contradiction(self):
        sf, qf = facts("source"), facts("sql")
        sf["source_kind"] = "FIXED_VALUE"
        result = triage.combine(saved(sf), saved(qf), bundle(), 6)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertTrue(result["contradiction"])
        qf["sql_effect"] = "PROTECTED"
        self.assertEqual(triage.combine(saved(sf), saved(qf), bundle(), 6)["verdict"], "LIKELY_FP")

    def test_no_context_gap_is_silently_removed(self):
        b = bundle(); b["missing_context"] = ["Missing helper return"]
        sf, qf = facts("source"), facts("sql")
        qf["sql_effect"] = "PROTECTED"
        r = triage.combine(saved(sf), saved(qf), b, 6)
        self.assertEqual(r["verdict"], "UNKNOWN")
        self.assertIn("Missing helper return", r["missing_context"])

    def test_fresh_requests_are_independent(self):
        a = triage.make_request("source", bundle(), 6)
        b = triage.make_request("sql", bundle(), 6)
        self.assertEqual(a["prompt"], b["prompt"])
        self.assertNotEqual(a["system"], b["system"])
        self.assertNotIn("Synthetic test response", b["prompt"])
        self.assertEqual(a["options"]["num_ctx"], 8192)


class PinnedHelpers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.files = {
            "src/main/java/demo/Entry.java": MAIN.replace('request.getParameter("name")', 'new Wrapper(request).read()'),
            "src/main/java/demo/Wrapper.java": '''package demo;
public class Wrapper {
 Request request;
 public Wrapper(Request r) { request = r; }
 public String read() {
  Choice x = Factory.create();
  return x.apply(request.getParameter("name"));
 }
}
''',
            "src/main/java/demo/Choice.java": "package demo;\npublic interface Choice { String apply(String x); }\n",
            "src/main/java/demo/Factory.java": '''package demo;
public class Factory {
 public static Choice create() {
  try (InputStream in = Factory.class.getClassLoader().getResourceAsStream("choice.properties")) {
   if (in == null) return new Fallback();
   Properties props = new Properties();
   props.load(in);
   String name = "demo." + props.getProperty("choice");
   return (Choice) Class.forName(name).getConstructor().newInstance();
  } catch (Exception e) { return new Fallback(); }
 }
}
''',
            "src/main/java/demo/Pass.java": 'package demo;\npublic class Pass implements Choice {\n public String apply(String x) {\n return x;\n }\n}\n',
            "src/main/java/demo/Fallback.java": 'package demo;\npublic class Fallback implements Choice {\n public String apply(String x) {\n return x;\n }\n}\n',
            "src/main/resources/choice.properties": "# PRIVATE_LABEL_SENTINEL\nchoice=Pass\n",
            "expectedresults.csv": "LABEL_FILE_MUST_NOT_BE_READ",
        }
        for name, data in self.files.items():
            p = self.root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(data)
        self.git("init", "-q"); self.git("add", ".")
        self.git("-c", "user.name=Offline Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def make_bundle(self):
        repo = context.Repository(self.root, self.commit)
        main = "src/main/java/demo/Entry.java"
        b = context.build(repo, main, self.files[main].encode())
        self.assertFalse(any("expectedresults" in p for p in repo.cache))
        return b

    def test_helper_resource_and_fallback_closure(self):
        b = self.make_bundle()
        self.assertEqual(len(b["files"]), 7)
        self.assertEqual(b["missing_context"], [])
        self.assertNotIn("PRIVATE_LABEL_SENTINEL", context.render(b))
        self.assertIn("choice=Pass", context.render(b))

    def test_worktree_edits_are_not_mixed_with_pinned_commit(self):
        (self.root / "src/main/java/demo/Pass.java").write_text("WRONG_WORKTREE")
        self.assertNotIn("WRONG_WORKTREE", context.render(self.make_bundle()))
        repo = context.Repository(self.root, self.commit)
        with self.assertRaisesRegex(ValueError, "không khớp"):
            context.build(repo, "src/main/java/demo/Entry.java", b"changed caller")

    def test_helper_evidence_is_resolved_from_its_own_file(self):
        b = self.make_bundle()
        ident = next(i for i, f in b["files"].items() if f["path"].endswith("/Wrapper.java"))
        sf = facts("source"); sf["source_evidence"] = [ident + ":7"]
        resolved = triage.validate(sf, "source", b, 6)
        self.assertTrue(any(x["file_id"] == ident and 'getParameter' in x["code"] for x in resolved))
        qf = facts("sql")
        with self.assertRaisesRegex(ValueError, "helper"):
            triage.validate(qf, "sql", b, 6)


class Checkpoints(unittest.TestCase):
    def attempt(self, request, stage, b, line, error=None):
        f = facts(stage)
        raw = json.dumps(f)
        return {"request_payload": request, "facts": f, "raw_output": raw,
            "ollama_response": {"done": True, "response": raw}, "elapsed_seconds": 1,
            "error_kind": error, "error": error, "resolved_evidence": []}

    def test_restart_does_not_generate_again(self):
        with tempfile.TemporaryDirectory() as d, patch.object(triage, "generate", side_effect=self.attempt) as gen:
            a = triage.ask("source", bundle(), 6, d)
            b = triage.ask("source", bundle(), 6, d)
            self.assertEqual(gen.call_count, 1)
            self.assertEqual(a, b)

    def test_one_repair_only_and_saved_errors_are_reused(self):
        def invalid(*args):
            return self.attempt(*args, error="INVALID_EVIDENCE")
        with tempfile.TemporaryDirectory() as d, patch.object(triage, "generate", side_effect=invalid) as gen:
            result = triage.ask("source", bundle(), 6, d)
            self.assertEqual(result["attempt_count"], 2)
            triage.ask("source", bundle(), 6, d)
            self.assertEqual(gen.call_count, 2)

    def test_changed_context_or_raw_facts_are_rejected(self):
        with tempfile.TemporaryDirectory() as d, patch.object(triage, "generate", side_effect=self.attempt):
            triage.ask("source", bundle(), 6, d)
            b = bundle(MAIN.replace('"name"', '"different"'))
            with self.assertRaisesRegex(ValueError, "Checkpoint"):
                triage.ask("source", b, 6, d)
            p = Path(d) / "source-attempt-1.json"
            saved = json.loads(p.read_text()); saved["attempt"]["facts"]["explanation"] = "tampered"
            p.write_text(json.dumps(saved))
            with self.assertRaisesRegex(ValueError, "Facts"):
                triage.ask("source", bundle(), 6, d)

    def test_started_call_requires_explicit_retry(self):
        with tempfile.TemporaryDirectory() as d, patch.object(triage, "generate", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                triage.ask("source", bundle(), 6, d)
        with tempfile.TemporaryDirectory() as d:
            with patch.object(triage, "generate", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    triage.ask("source", bundle(), 6, d)
            with patch.object(triage, "generate", side_effect=self.attempt) as gen:
                with self.assertRaisesRegex(ValueError, "retry-incomplete"):
                    triage.ask("source", bundle(), 6, d)
                self.assertEqual(gen.call_count, 0)
                triage.ask("source", bundle(), 6, d, retry_incomplete=True)
                self.assertEqual(gen.call_count, 1)

    def test_transport_failure_not_repaired(self):
        def failed(*args):
            return self.attempt(*args, error="OLLAMA_TIMEOUT")
        with tempfile.TemporaryDirectory() as d, patch.object(triage, "generate", side_effect=failed) as gen:
            result = triage.ask("source", bundle(), 6, d)
            self.assertEqual(gen.call_count, 1)
            self.assertEqual(result["error_kind"], "OLLAMA_TIMEOUT")

    def test_truncated_or_context_full_never_accepted(self):
        request = triage.make_request("source", bundle(), 6)
        for extra, error in (({"done_reason": "length"}, "TRUNCATED_OUTPUT"),
                             ({"prompt_eval_count": 8000}, "CONTEXT_LIMIT")):
            class Response:
                def raise_for_status(self): pass
                def json(self):
                    return {"done": True, "response": json.dumps(facts("source")), "prompt_eval_count": 100, **extra}
            with patch.object(triage.core.requests, "post", return_value=Response()):
                result = triage.generate(request, "source", bundle(), 6)
                self.assertEqual(result["error_kind"], error)
                self.assertIsNone(result["facts"])


if __name__ == "__main__":
    unittest.main()
