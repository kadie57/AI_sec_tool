from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from analyzers.path_traversal.evidence.path_cpg import operand_value_view, parse_query, project_sites
from analyzers.path_traversal.path_llm_experiment import OPERAND_FIRST_LAYOUT, assess_response, plan
from analyzers.path_traversal.path_project_flow_experiment import export_project_flows, stage_helpers
from analyzers.path_traversal.prepare_path_evidence import export_evidence
from common.ollama_review import read, write

from .test_path_baseline import fixture


EXAMPLE = """import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.servlet.ServletRequest;
class Example {
    void inspect(ServletRequest req) throws Exception {
        String name = Helper.label(req);
        var item = Path.of(name);
        Files.readString(item);
        File other = new File("fixed.txt");
        other.exists();
    }
}
"""
HELPER = """import javax.servlet.ServletRequest;
class Helper {
    static String label(ServletRequest request) {
        return request.getParameter("document");
    }
}
"""
REQUEST = """package javax.servlet;
public interface ServletRequest { String getParameter(String key); }
"""


def export_fixture(root, *, value_case=False):
    issues = [
        {"key": "read", "rule": "findsecbugs:PATH_TRAVERSAL_IN", "component": "test:Example.java",
         "line": 9, "message": "This API (java/nio/file/Files.readString(Ljava/nio/file/Path;)Ljava/lang/String;)"},
        {"key": "metadata", "rule": "findsecbugs:PATH_TRAVERSAL_IN", "component": "test:Example.java",
         "line": 11, "message": "This API (java/io/File.exists()Z)"},
    ]
    example, helper = EXAMPLE, HELPER
    if value_case:
        example = example.replace('new File("fixed.txt")', "new File(Helper.fixedName(name))")
        helper = helper.rsplit("}", 1)[0] + """    static String fixedName(String input) {
        String labels = "DEF";
        switch (labels.charAt(1)) {
            case 'D':
                return input;
            default:
                return "fixed.txt";
        }
    }
}
"""
    collection, sources = fixture(root, example, issues)
    manifest = read(collection / "manifest.json")
    for name, code in (("Helper.java", helper), ("javax/servlet/ServletRequest.java", REQUEST)):
        target = sources / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
        manifest["source_hashes"][name] = sha256(target.read_bytes()).hexdigest()
    write(collection / "manifest.json", manifest)
    base = root / "base"
    export_evidence(collection, sources, base)
    return base / "path_evidence.jsonl", collection, sources


class ProjectFlowTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "Git is needed")
    def test_uses_helpers_at_collection_commit_and_excludes_other_samples(self):
        sample = "src/main/java/testcode/Example.java"
        helper = "src/main/java/Helper.java"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            repo, project = root / "repo", root / "project"
            repo.mkdir()

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

            git("init", "-q")
            for name, code in ((sample, EXAMPLE), (helper, HELPER), ("src/main/java/testcode/Other.java", "class Other {}")):
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(code, encoding="utf-8")
            git("add", "src")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                "-c", "commit.gpgsign=false", "commit", "-qm", "Fixture snapshot")
            commit = git("rev-parse", "HEAD")
            (repo / helper).write_text("class Modified {}\n", encoding="utf-8")
            frozen = {"prefix/" + sample: {"sha256": sha256(EXAMPLE.encode()).hexdigest()}}
            helpers = stage_helpers(repo, commit, frozen, project)
            self.assertEqual(list(helpers), [helper])
            self.assertEqual((project / helper).read_text(), HELPER)
            self.assertEqual(helpers[helper]["sha256"], sha256(HELPER.encode()).hexdigest())
            with self.assertRaisesRegex(ValueError, "differs from the pinned"):
                stage_helpers(repo, commit, {"prefix/" + sample: {"sha256": "0" * 64}}, project)

    def test_missing_sources_and_ambiguous_operands_remain_separate(self):
        sources = [("Helper.java", 4, "getParameter")]
        targets = [("Example.java", 9, "readString", 1), ("Example.java", 11, "exists", 0)]
        traces, matched = parse_query("PATH_FLOW\tSOURCE\t0\t0\nPATH_FLOW\tSINK\t0\t1\t1\n"
                                     "PATH_FLOW\tSINK\t1\t2\t2\n", sources, targets)
        self.assertEqual(matched, 0)
        self.assertEqual(traces[targets[0]]["status"], "no_matched_http_read")
        self.assertEqual(traces[targets[1]]["status"], "operand_not_unique_in_cpg")
        with self.assertRaisesRegex(ValueError, "did not report all"):
            parse_query("", sources, targets)

    @unittest.skipUnless(shutil.which("javac"), "JDK 17 is needed")
    def test_local_hash_map_tracks_the_selected_key_at_the_file_operand(self):
        example = """import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletRequest;
class Example {
    static String select(String value, String key) {
        Map<String, Object> options = new HashMap<>();
        options.put("preset", "notes.txt");
        options.put("submitted", value);
        options.put("updated", value);
        options.put("updated", "replace.txt"); // final_put
        return (String) options.get(key);
    }

    static String aliased(String value) {
        var options = new HashMap<String, String>();
        options.put("preset", "notes.txt");
        var alias = options;
        alias.put("preset", value);
        return options.get("preset");
    }

    static String dynamicWrite(String key, String value) {
        var options = new HashMap<String, String>();
        options.put("preset", "notes.txt");
        options.put(key, value);
        return options.get("preset");
    }

    static String differentBranches(String value, boolean choice) {
        var options = new HashMap<String, String>();
        options.put("preset", "notes.txt");
        if (choice) options.put("preset", value);
        return options.get("preset");
    }

    void inspect(ServletRequest request, boolean choice) throws Exception {
        String name = request.getParameter("document");
        Files.newInputStream(Paths.get(select(name, "preset"))); // fixed
        Files.newInputStream(Paths.get(select(name, "submitted"))); // submitted
        Files.newInputStream(Paths.get(select(name, "updated"))); // overwritten
        Files.newInputStream(Paths.get(select(name, name))); // unknown_key
        Files.newInputStream(Paths.get(aliased(name))); // alias
        Files.newInputStream(Paths.get(dynamicWrite(name, name))); // dynamic_write
        Files.newInputStream(Paths.get(differentBranches(name, choice))); // unresolved_branch
    }
}
"""
        code = {"Example.java": example, "javax/servlet/ServletRequest.java": REQUEST}
        with TemporaryDirectory() as directory:
            root = Path(directory)
            project, graph = root / "project", root / "graph"
            graph.mkdir()
            for name, source in code.items():
                target = project / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            errors, indexed = project_sites({name: {"masked_source": source} for name, source in code.items()},
                                            project, graph, (), value_facts=True)
        self.assertEqual(errors, 0)
        markers = {line.rsplit("// ", 1)[1]: n for n, line in enumerate(example.splitlines(), 1) if "// " in line}

        def proof(marker):
            site, = indexed["Example.java", markers[marker], "newInputStream"]
            return site.get("value_by_operand", {}).get(1, ("unknown", []))

        self.assertEqual(proof("fixed")[0], "fixed_value")
        self.assertEqual(proof("submitted")[0], "external_input_in_expression")
        origin, facts = proof("overwritten")
        self.assertEqual(origin, "fixed_value")
        self.assertEqual([line for _, line, _, role in facts if role == "map_put_for_key"], [markers["final_put"]])
        self.assertTrue({"map_get_by_key", "helper_return"} <= {role for _, _, _, role in facts})
        for marker in ("unknown_key", "alias", "dynamic_write", "unresolved_branch"):
            with self.subTest(marker=marker):
                self.assertEqual(proof(marker)[0], "unknown")

    @unittest.skipUnless(shutil.which("javac"), "JDK 17 is needed")
    def test_local_array_list_tracks_index_shifts_and_resolved_overloads(self):
        example = """import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletRequest;
class Example {
    static String afterRemoval(String input, int index) {
        List<Object> values = new ArrayList<>();
        values.add("first.txt");
        values.add(input);
        values.add("last.txt"); // selected_append
        values.remove(0); // removal
        return (String) values.get(index); // lookup
    }

    static String unsupportedOverload(String input) {
        var values = new ArrayList<String>();
        values.add(input);
        values.add("other.txt");
        values.remove("other.txt");
        return values.get(0);
    }

    static String unknownRemoval(String input, int index) {
        var values = new ArrayList<String>();
        values.add("first.txt");
        values.add(input);
        values.remove(index);
        return values.get(0);
    }

    static String withFallback(String input, boolean chooseList) {
        String result = "fallback.txt"; // fallback_definition
        if (chooseList) result = afterRemoval(input, 1);
        return result;
    }

    void inspect(ServletRequest request, int index, boolean chooseList) throws Exception {
        String input = request.getParameter("document");
        Files.newInputStream(Paths.get(afterRemoval(input, 1))); // fixed_list
        Files.newInputStream(Paths.get(afterRemoval(input, 0))); // input_list
        Files.newInputStream(Paths.get(afterRemoval(input, index))); // unknown_lookup
        Files.newInputStream(Paths.get(afterRemoval(input, 2))); // out_of_bounds
        Files.newInputStream(Paths.get(unsupportedOverload(input))); // object_remove
        Files.newInputStream(Paths.get(unknownRemoval(input, index))); // unknown_remove
        Files.newInputStream(Paths.get(withFallback(input, chooseList))); // fixed_alternatives
        String prefix = System.getProperty("user.dir").replace(' ', '_');
        new File(prefix + "/" + afterRemoval(input, 1)).exists(); // replaced_config
    }
}
"""
        code = {"Example.java": example, "javax/servlet/ServletRequest.java": REQUEST}
        with TemporaryDirectory() as directory:
            root = Path(directory)
            project, graph = root / "project", root / "graph"
            graph.mkdir()
            for name, source in code.items():
                target = project / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            errors, indexed = project_sites({name: {"masked_source": source} for name, source in code.items()},
                                            project, graph, (), value_facts=True)
        self.assertEqual(errors, 0)
        markers = {line.rsplit("// ", 1)[1]: n for n, line in enumerate(example.splitlines(), 1) if "// " in line}

        def proof(marker, method="newInputStream", operand=1):
            site, = indexed["Example.java", markers[marker], method]
            return site.get("value_by_operand", {}).get(operand, ("unknown", []))

        origin, facts = proof("fixed_list")
        self.assertEqual(origin, "fixed_value")
        refs = {role: line for _, line, _, role in facts}
        self.assertEqual(refs["list_append"], markers["selected_append"])
        self.assertEqual(refs["list_remove_index"], markers["removal"])
        self.assertEqual(refs["list_get_by_index"], markers["lookup"])
        self.assertEqual(proof("input_list")[0], "external_input_in_expression")
        for marker in ("unknown_lookup", "out_of_bounds", "object_remove", "unknown_remove"):
            with self.subTest(marker=marker):
                self.assertEqual(proof(marker)[0], "unknown")
        origin, facts = proof("fixed_alternatives")
        self.assertEqual(origin, "fixed_value")
        refs = {(line, role) for _, line, _, role in facts}
        self.assertIn((markers["fallback_definition"], "fixed_alternative_local_definition"), refs)
        self.assertIn((markers["removal"], "fixed_alternative_list_remove_index"), refs)
        self.assertIn((markers["lookup"], "fixed_alternative_list_get_by_index"), refs)
        origin, facts = proof("replaced_config", "exists", 0)
        self.assertEqual(origin, "configuration_value")
        self.assertIn("string_constant_char_replacement", {role for _, _, _, role in facts})

    @unittest.skipUnless(shutil.which("javac"), "JDK 17 is needed")
    def test_typed_header_summary_tracks_branch_and_respects_overwrite(self):
        example = """import java.io.File;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;
class Example {
    static String forward(String value) {
        String selector = "DEF";
        switch (selector.charAt(1)) {
            case 'E': return value;
            default: return "fixed.txt";
        }
    }

    void inspect(HttpServletRequest request, Enumeration<String> unrelated) throws Exception {
        var headers = request.getHeaders("document");
        var alias = headers;
        String path = "";
        if (alias != null && alias.hasMoreElements()) {
            path = alias.nextElement();
        }
        path = URLDecoder.decode(path, "UTF-8");
        new File(forward(path)).exists(); // via_helper
        new File(URLDecoder.decode(path, StandardCharsets.UTF_8)).exists(); // charset_overload
        path = "fixed.txt";
        new File(path).exists(); // overwritten
        new File(unrelated.nextElement()).exists(); // unrelated_receiver
        new File(URLDecoder.decode("fixed.txt", request.getHeader("encoding"))).exists(); // encoding_only
        var otherHeaders = request.getHeaders("other");
        if (alias.hasMoreElements()) {
            new File(otherHeaders.nextElement()).exists(); // different_guard_receiver
        }
    }
}
"""
        request = """package javax.servlet.http;
import java.util.Enumeration;
public interface HttpServletRequest {
    Enumeration<String> getHeaders(String name);
    String getHeader(String name);
}
"""
        code = {"Example.java": example, "javax/servlet/http/HttpServletRequest.java": request}
        with TemporaryDirectory() as directory:
            root = Path(directory)
            project, graph = root / "project", root / "graph"
            graph.mkdir()
            for name, source in code.items():
                target = project / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            errors, indexed = project_sites({name: {"masked_source": source} for name, source in code.items()},
                                            project, graph, (), value_facts=True)

        self.assertEqual(errors, 0)

        def operand_value(marker):
            line = next(n for n, text in enumerate(example.splitlines(), 1) if text.endswith(f"// {marker}"))
            site, = indexed["Example.java", line, "exists"]
            return site.get("value_by_operand", {}).get(0)

        expected_roles = {"http_header_enumeration", "header_element_from_receiver", "url_decode_from_argument_1"}
        origin, facts = operand_value("via_helper")
        self.assertEqual(origin, "possible_external_input_in_expression")
        self.assertTrue(expected_roles | {"helper_return"} <= {fact[-1] for fact in facts})
        view = operand_value_view(origin, facts, {"Example.java": example.splitlines()},
                                  lambda _, line: {"file_id": "F0", "line": line})
        guard, = view["request_input_branch"]["guards_true"]
        decision, = view["resolved_helper_branches"]["decisions"]
        self.assertIn("alias.hasMoreElements()", guard["code"])
        self.assertIn("case 'E'", decision["code"])
        self.assertEqual(decision["decision"], "switch selects this case")
        origin, facts = operand_value("charset_overload")
        self.assertEqual(origin, "possible_external_input_in_expression")
        self.assertTrue(expected_roles <= {fact[-1] for fact in facts})
        origin, facts = operand_value("overwritten")
        self.assertEqual(origin, "fixed_value")
        self.assertTrue(expected_roles.isdisjoint(fact[-1] for fact in facts))
        self.assertIsNone(operand_value("unrelated_receiver"))
        self.assertIsNone(operand_value("encoding_only"))
        _, unrelated_facts = operand_value("different_guard_receiver")
        self.assertNotIn("header_availability_guard_true", {fact[-1] for fact in unrelated_facts})

    @unittest.skipUnless(shutil.which("javac"), "JDK 17 is needed")
    def test_prunes_conflicting_flow_and_keeps_a_verified_http_operand(self):
        output = (
            "PATH_FLOW\tSOURCE\t0\t1\n"
            "PATH_FLOW\tSINK\t0\t1\t1\nPATH_FLOW\tCOUNT\t0\t1\n"
            "PATH_FLOW\tNODE\t0\t0\t0\tHelper.java\t4\tlabel\tCall\n"
            "PATH_FLOW\tNODE\t0\t0\t0\tExample.java\t9\tinspect\tIdentifier\n"
            "PATH_FLOW\tSINK\t1\t1\t1\nPATH_FLOW\tCOUNT\t1\t1\n"
            "PATH_FLOW\tNODE\t1\t0\t0\tHelper.java\t4\tlabel\tCall\n"
            "PATH_FLOW\tNODE\t1\t0\t0\tExample.java\t11\tinspect\tIdentifier\n"
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, collection, sources = export_fixture(root, value_case=True)
            dest = root / "with-facts"
            with patch("analyzers.path_traversal.path_project_flow_experiment.run_joern_script", return_value=output):
                export_project_flows(evidence, collection, sources, dest, "sha256:" + "a" * 64, value_facts=True)
            _, items = plan(dest / "path_evidence.jsonl")
            read_operation, = items["read"][0]["project_flow"]["operations"]
            fixed_operation, = items["metadata"][0]["project_flow"]["operations"]
            self.assertEqual(read_operation["target"]["java_operand_value"]["origin"], "external_input_in_expression")
            self.assertEqual(len(read_operation["paths"]), 1)
            self.assertEqual(fixed_operation["target"]["java_operand_value"]["origin"], "fixed_value")
            roles = {step["role"] for step in fixed_operation["target"]["java_operand_value"]["steps"]}
            self.assertTrue({"switch_case_selected", "helper_return"} <= roles)
            self.assertEqual(fixed_operation["paths"], [])
            config, operand_first = plan(dest / "path_evidence.jsonl", evidence_layout=OPERAND_FIRST_LAYOUT)
            self.assertEqual(config["evidence_layout"], OPERAND_FIRST_LAYOUT)
            self.assertEqual(operand_first["read"][1], items["read"][1])
            baseline = items["metadata"][1]
            request = operand_first["metadata"][1]
            payload = json.loads(request["prompt"])
            operand, = payload.pop("file_operand_evidence")
            self.assertEqual(payload, json.loads(baseline["prompt"]))
            target = fixed_operation["target"]
            self.assertEqual((operand["api"]["file_id"], operand["api"]["line"]), ("F0", target["api_line"]))
            self.assertEqual(operand["path_operand"], {
                "file_id": "F0", "line": target["line"], "position": "receiver",
            })
            self.assertEqual(operand["java_value"]["supporting_steps"], target["java_operand_value"]["steps"])
            self.assertEqual(request["system"], baseline["system"])
            removal, = read(dest / "graph/pruned-candidates.json")
            self.assertEqual(removal["reason"], "verified_fixed_operand")
            self.assertEqual(removal["issue_id"], "metadata")

    @unittest.skipUnless(shutil.which("javac"), "JDK 17 is needed")
    def test_project_export_and_helper_coordinates_in_requests(self):
        fake_output = """PATH_FLOW\tSOURCE\t0\t1
PATH_FLOW\tSINK\t0\t1\t1
PATH_FLOW\tCOUNT\t0\t1
PATH_FLOW\tNODE\t0\t0\t0\tHelper.java\t4\tlabel\tCall
PATH_FLOW\tNODE\t0\t0\t0\tExample.java\t7\tinspect\tCall
PATH_FLOW\tNODE\t0\t0\t0\tExample.java\t9\tinspect\tIdentifier
PATH_FLOW\tSINK\t1\t1\t1
PATH_FLOW\tCOUNT\t1\t0
"""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, collection, sources = export_fixture(root)
            output = root / "project-export"
            image = os.getenv("PATH_CPG_TEST_IMAGE")
            if image:
                export_project_flows(evidence, collection, sources, output, image)
            else:
                with patch("analyzers.path_traversal.path_project_flow_experiment.run_joern_script",
                           return_value=fake_output) as runner:
                    export_project_flows(evidence, collection, sources, output, "sha256:" + "a" * 64)
                    runner.assert_called_once()
            endpoints = (output / "graph/endpoints.tsv").read_text()
            self.assertIn("readString\t1\n", endpoints)
            self.assertIn("exists\t0\n", endpoints)
            config, items = plan(output / "path_evidence.jsonl")
            self.assertEqual(config["request_version"], 3)
            row, request = items["read"]
            payload = json.loads(request["prompt"])
            path = payload["project_flow"]["operations"][0]["paths"][0]
            self.assertEqual(path["source"]["file_id"], "F1")
            self.assertEqual(path["source"]["line"], 4)
            self.assertIn('F1:4 return request.getParameter("document");', payload["files"][1]["numbered_source"])
            self.assertNotIn("real_vulnerability", request["prompt"])
            self.assertEqual(items["metadata"][0]["project_flow"]["operations"][0]["status"], "no_candidate_path")
            response = {"verdict": "UNKNOWN", "explanation": "Chưa xác minh giới hạn thư mục.",
                        "citations": [{"file_id": "F0", "line": 9}, {"file_id": "F1", "line": 4}]}
            raw = {"ollama_response": {"done": True, "done_reason": "stop", "prompt_eval_count": 100,
                                       "response": json.dumps(response)}}
            assess_response(raw, row)
            self.assertEqual(raw["assessment"], response)
