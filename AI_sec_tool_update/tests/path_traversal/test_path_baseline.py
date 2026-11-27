from hashlib import sha256
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from analyzers.path_traversal.path_llm_experiment import BASELINE_PROFILE, PATH_SCHEMA, PROMPT, assess_response, plan, score
from analyzers.path_traversal.prepare_path_evidence import export_evidence, load_collection, scanner_api
from common.ollama_review import read, run_requests, write


SOURCE = """import java.io.File;
import java.io.FileInputStream;
class Example {
    void read() throws Exception {
        File file =
            new File(new File("base"), "document.txt");
        try (var stream = new FileInputStream(file)) {}
    }
}
"""
MESSAGE = "This API (java/io/File.<init>(Ljava/io/File;Ljava/lang/String;)V) reads a file"


def fixture(root, source=SOURCE, issues=None):
    collection = root / "collection"
    collection.mkdir()
    sources = root / "sources"
    sources.mkdir()
    (sources / "Example.java").write_text(source, encoding="utf-8")
    (sources / "Unwarned.java").write_text("class Unwarned {}\n", encoding="utf-8")
    hashes = {file.name: sha256(file.read_bytes()).hexdigest() for file in sources.iterdir()}
    write(collection / "manifest.json", {"state": "COLLECTED", "analysis_id": "scan", "project": "test",
                                          "source_hashes": hashes})
    defaults = [
        {"key": "reported-1", "rule": "findsecbugs:PATH_TRAVERSAL_IN", "component": "test:Example.java",
         "textRange": {"startLine": 5, "endLine": 5}, "message": MESSAGE},
        {"key": "reported-2", "rule": "findsecbugs:PATH_TRAVERSAL_IN", "component": "test:Example.java",
         "textRange": {"startLine": 5, "endLine": 5},
         "message": "This API (java/io/File.<init>(Ljava/lang/String;)V) reads a file"},
        {"key": "other-cwe", "rule": "findsecbugs:SQL_INJECTION_JDBC", "component": "test:Example.java"},
    ]
    write(collection / "issues.json", {"issues": defaults if issues is None else issues})
    return collection, sources


class PathBaselineTest(unittest.TestCase):
    @staticmethod
    def local_path_uses(root, source, api):
        collection, sources = fixture(root, source, [{
            "key": "use", "rule": "findsecbugs:PATH_TRAVERSAL_IN", "component": "test:Example.java",
            "line": next(n for n, text in enumerate(source.splitlines(), 1) if "// warning" in text),
            "message": f"This API ({api}) reads a file",
        }])
        output = root / "export"
        export_evidence(collection, sources, output)
        record = json.loads((output / "path_evidence.jsonl").read_text())
        return record["java_evidence"]["same_method_path_use"]["uses"]

    def test_reported_signature_includes_array_and_primitive_types(self):
        api = scanner_api("This API (java/nio/file/Paths.get(Ljava/lang/String;[Ljava/lang/String;I)Ljava/nio/file/Path;) reads a file")
        self.assertEqual(api, {"owner": "java.nio.file.Paths", "method": "get",
                               "parameters": ["java.lang.String", "java.lang.String[]", "int"]})

    def test_changed_java_snapshot_is_rejected(self):
        with TemporaryDirectory() as directory:
            collection, sources = fixture(Path(directory))
            (sources / "Example.java").write_text(SOURCE + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs from the SonarQube snapshot"):
                load_collection(collection, sources)

    @unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "JDK 17 is needed")
    def test_path_alias_branch_merge_and_overwrite(self):
        code = """import java.io.File;
import java.io.FileInputStream;
class Example {
    void inspect(boolean change) throws Exception {
        File original = new File("base.txt"); // warning
        File alias = original;
        alias.exists();
        if (change) alias = new File("different.txt");
        alias.exists();
        alias = new File("third.txt");
        alias.exists();
        if (false && original.exists()) return;
        try (var stream = new FileInputStream(original)) {}
    }
}
"""
        with TemporaryDirectory() as directory:
            facts = self.local_path_uses(Path(directory), code, "java/io/File.<init>(Ljava/lang/String;)V")
        self.assertEqual([(x["operation"]["line"], x["operation"]["role"], x["path_input"]) for x in facts],
                         [(7, "file_metadata", "receiver"), (13, "file_read", "argument_1")])
        self.assertTrue(all(x["origin"] == "fixed_value" for x in facts))

    @unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "JDK 17 is needed")
    def test_constant_branch_and_returned_read_preserve_the_selected_path(self):
        code = """import java.nio.file.Files;
import java.nio.file.Path;
class Example {
    String read(String other) throws Exception {
        int threshold = 12;
        String name;
        if (3 * 5 > threshold) name = "fixed.txt";
        else name = other;
        var chosen = Path.of(name); // warning
        return Files.readString(chosen.normalize());
    }
}
"""
        with TemporaryDirectory() as directory:
            fact, = self.local_path_uses(Path(directory), code,
                                        "java/nio/file/Path.of(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;")
        self.assertEqual(fact["origin"], "fixed_value")
        self.assertIn(7, fact["fixed_component_definition_lines"])
        self.assertNotIn(8, fact["evidence_lines"])
        self.assertEqual(fact["operation"]["method"], "readString")

    @unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "JDK 17 is needed")
    def test_overloaded_anchors_and_sample_vs_warning_scoring(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            collection, sources = fixture(root)
            output = root / "export"
            self.assertEqual(export_evidence(collection, sources, output), 2)
            evidence = output / "path_evidence.jsonl"
            config, items = plan(evidence, BASELINE_PROFILE)
            self.assertEqual(list(items), ["reported-1", "reported-2"])
            for key, first_parameter in (("reported-1", "java.io.File"), ("reported-2", "java.lang.String")):
                row, request = items[key]
                details = row["java_evidence"]
                self.assertEqual(details["anchor_status"], "one_typed_api")
                anchor, = details["anchors"]
                self.assertEqual(anchor["parameters"][0], first_parameter)
                self.assertEqual(anchor["role"], "path_construction")
                self.assertEqual(anchor["line"], 6)
                self.assertTrue(any(site["role"] == "file_read" and site["line"] == 7
                                    for site in details["sites_in_anchor_methods"]))
                self.assertNotIn("real_vulnerability", request["prompt"])
                self.assertIn("F0:6 new File", request["prompt"])
                self.assertEqual(request["format"]["properties"]["citations"]["minItems"], 2)

            results = root / "llm"
            run_requests(items, results, 1, config, PROMPT, PATH_SCHEMA, assess_response, dry_run=True)
            manifest = read(results / "manifest.json")
            write(results / "manifest.json", {**manifest, "mode": "ollama", "model_digest": "test-model"})
            for number, (row, _) in enumerate(items.values(), 1):
                case_path = results / f"case-{number:04d}.json"
                case = read(case_path)
                case["ollama_response"] = {
                    "done": True, "done_reason": "stop", "prompt_eval_count": 30,
                    "response": json.dumps({"verdict": "LIKELY_FP", "explanation": "Fixed file name.",
                                            "citations": [{"file_id": "F0", "line": line} for line in (5, 6)]}),
                }
                assess_response(case, row)
                write(case_path, case)
            reference = root / "labels.json"
            write(reference, {"labels": {"Example": {"cwe": "22", "category": "pathtraver", "real_vulnerability": False},
                                         "Unwarned": {"cwe": "22", "category": "pathtraver", "real_vulnerability": True}}})
            summary = score(evidence, results, collection, reference)
            self.assertEqual(summary["sonarqube"]["sample_confusion"], {"FP": 1, "FN": 1})
            self.assertEqual(summary["qwen"]["counts"], {"TN": 2})
