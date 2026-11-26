from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

from sql_pipeline.evidence.sql_endpoint_specifications import infer_specifications


SERVLET_JAR = Path.home() / ".m2/repository/javax/javaee-api/8.0.1/javaee-api-8.0.1.jar"
CODEC_JAR = Path.home() / ".m2/repository/commons-codec/commons-codec/1.23.0/commons-codec-1.23.0.jar"


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "A full JDK is required")
class SqlJdbcValueEvidenceTest(unittest.TestCase):
    def probe(self, source, dependencies=(), caller=None, *, selected=None, experimental_dispatch_evidence=False):
        alert, = (n for n, line in enumerate(source.splitlines(), 1) if "sink.execute(" in line)
        item = SimpleNamespace(start=alert, end=alert)
        bundle = {"files": {"F0": {"kind": "JAVA", "path": "Example.java", "masked_source": source}}}
        if caller is not None:
            bundle["files"]["F1"] = {"kind": "JAVA", "path": "Caller.java", "masked_source": caller}
            bundle["snapshot_callers"] = ["F1"]
        deps = [{"path": str(jar)} for jar in dependencies]
        with tempfile.TemporaryDirectory() as directory:
            result = infer_specifications(item, bundle, selected or {}, deps, Path(directory) / "java.log",
                                          value_evidence=True, experimental_dispatch_evidence=experimental_dispatch_evidence)
        self.assertEqual(result["sink_resolution"], "one_verified_signature")
        argument, = result["jdbc_value_evidence"]["arguments"]
        self.assertEqual(argument["call"]["line"], alert)
        return argument

    def dispatch_example(self, declaration, second_body, *, factory=False):
        source = """import java.sql.Statement;
class Example {
  KIND interface Formatter PERMITS { String format(String input); }
  static final class Copy implements Formatter {
    public String format(String input) { return input; }
  }
  static final class Builder implements Formatter {
    boolean replace;
    public String format(String input) { SECOND_BODY }
  }
  void run(Statement sink, Formatter formatter, String outside) throws Exception {
    String text = formatter.format(outside);
    sink.execute("SELECT " + text);
  }
}
""".replace("KIND", "sealed" if declaration == "sealed" else "")
        source = source.replace("PERMITS", "permits Copy, Builder" if declaration == "sealed" else "")
        source = source.replace("SECOND_BODY", second_body)
        if factory:
            source = source.replace("String text = formatter.format(outside);",
                                    "Formatter local = create(); String text = local.format(outside);")
            source = source.rstrip().removesuffix("}") + "  static Formatter create() { return new Copy(); }\n}\n"
        edge = {"file_id": "F0", "line": 12, "name": "format", "possible_targets": [
            {"file_id": "F0", "line": line} for line in (3, 5, 9)]}
        return self.probe(source, selected={"anchored_paths": {"paths": [{"dispatch": [edge]}]}},
                          experimental_dispatch_evidence=True)

    def test_agreeing_dispatch_targets_report_their_proven_scope(self):
        for kind, scope in (("sealed", "sealed_final_targets"), ("open", "listed_candidates_only")):
            with self.subTest(kind=kind):
                result = self.dispatch_example(kind, 'if (input == null) return ""; return new StringBuilder(input).toString();')
                self.assertEqual(result["status"], "unknown")
                group, = result["dispatch_evidence"]
                self.assertEqual(group["scope"], scope)
                self.assertEqual(group["condition"], "non_null_string_argument")
                self.assertEqual([target["owner"] for target in group["targets"]], ["Example.Copy", "Example.Builder"])

    def test_disagreeing_or_runtime_dependent_dispatch_keeps_unknown(self):
        for body in ('return "fixed";', 'if (replace) return "fixed"; return input;'):
            with self.subTest(body=body):
                result = self.dispatch_example("sealed", body)
                self.assertEqual(result["status"], "unknown")
                self.assertNotIn("dispatch_evidence", result)

    def test_dispatch_factory_context_tracks_the_bound_local_and_direct_return(self):
        result = self.dispatch_example("open", "return input;", factory=True)
        group, = result["dispatch_evidence"]
        factory = group["receiver_factory"]
        self.assertEqual(group["scope"], "listed_candidates_only")
        self.assertEqual(factory["initializer"], {"file_id": "F0", "line": 12})
        self.assertEqual(factory["direct_returns"], [{"file_id": "F0", "line": 15, "allocated_type": "Example.Copy"}])

    @unittest.skipUnless(CODEC_JAR.is_file(), "Commons Codec library is unavailable")
    def test_base64_roundtrip_preserves_fixed_origin_with_default_charset(self):
        result = self.probe("""import java.sql.Statement;
import org.apache.commons.codec.binary.Base64;
class Example {
  void run(Statement sink) throws Exception {
    String label = "internal";
    String text = new String(Base64.decodeBase64((Base64.encodeBase64(label.getBytes()))));
    sink.execute("SELECT " + text);
  }
}
""", (CODEC_JAR,))
        self.assertEqual(result["status"], "request_independent_sql_text")
        roles = {fact["role"] for fact in result["evidence"]}
        self.assertTrue({"string_to_bytes", "base64_encode", "base64_decode", "bytes_to_string"} <= roles)

    @unittest.skipUnless(CODEC_JAR.is_file(), "Commons Codec library is unavailable")
    def test_base64_roundtrip_uses_known_charset_and_refuses_mismatched_charset(self):
        source = """import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.binary.Base64;
class Example {
  void run(Statement sink, String outside) throws Exception {
    String text = new String(Base64.decodeBase64(Base64.encodeBase64("café".getBytes(StandardCharsets.UTF_8))),
                             StandardCharsets.CHARSET);
    sink.execute(text.equals("café") ? "SELECT 1" : outside);
  }
}
"""
        expected = self.probe(source.replace("CHARSET", "UTF_8"), (CODEC_JAR,))
        self.assertEqual(expected["status"], "constant_sql_text")
        mismatched = self.probe(source.replace("CHARSET", "US_ASCII"), (CODEC_JAR,))
        self.assertEqual(mismatched["status"], "unknown")

    @unittest.skipUnless(CODEC_JAR.is_file() and SERVLET_JAR.is_file(), "Commons Codec and Servlet jars are required")
    def test_base64_roundtrip_preserves_verified_request_origin(self):
        result = self.probe("""import java.sql.Statement;
import javax.servlet.ServletRequest;
import org.apache.commons.codec.binary.Base64;
class Example {
  void run(Statement sink, ServletRequest request) throws Exception {
    String text = request.getParameter("label");
    String transformed = new String(Base64.decodeBase64(Base64.encodeBase64(text.getBytes())));
    sink.execute("SELECT " + transformed);
  }
}
""", (CODEC_JAR, SERVLET_JAR))
        self.assertEqual(result["status"], "external_input_contributes")
        self.assertIn({"file_id": "F0", "line": 6, "role": "servlet_request_read"}, result["evidence"])
        self.assertIn({"file_id": "F0", "line": 7, "role": "base64_decode"}, result["evidence"])

    @unittest.skipUnless(CODEC_JAR.is_file(), "Commons Codec library is unavailable")
    def test_base64_from_an_unresolved_argument_stays_unknown(self):
        result = self.probe("""import java.sql.Statement;
import org.apache.commons.codec.binary.Base64;
class Example {
  void run(Statement sink, String outside) throws Exception {
    byte[] encoded = Base64.encodeBase64(outside.getBytes());
    sink.execute("SELECT " + new String(Base64.decodeBase64(encoded)));
  }
}
""", (CODEC_JAR,))
        self.assertEqual(result["status"], "unknown")

    def test_incoming_call_uses_symbol_and_propagates_the_argument(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void run(Statement sink, String value) throws Exception {
    sink.execute("SELECT " + value);
  }
  void run(Statement sink, int value) {}
}
""", caller="""import java.sql.Statement;
class Caller {
  void run(Statement sink) throws Exception {
    String value = "constant";
    (new Example()).run(sink, 2);
    (new Example()).run(sink, value);
  }
}
""")
        self.assertEqual(result["status"], "constant_sql_text")
        self.assertIn({"file_id": "F1", "line": 6, "role": "caller_argument"}, result["evidence"])
        self.assertIn({"file_id": "F0", "line": 3, "role": "callee_parameter"}, result["evidence"])

    def test_conflicting_incoming_call_sites_keep_the_value_unknown(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  static void run(Statement sink, String value) throws Exception {
    sink.execute("SELECT " + value);
  }
}
""", caller="""import java.sql.Statement;
class Caller {
  void run(Statement sink, String outside) throws Exception {
    Example.run(sink, "constant");
    Example.run(sink, outside);
  }
}
""")
        self.assertEqual(result["status"], "unknown")

    @unittest.skipUnless(SERVLET_JAR.is_file(), "Servlet library is unavailable")
    def test_array_list_remove_shifts_the_selected_slot(self):
        source = """import java.sql.Statement;
import javax.servlet.ServletRequest;
import java.util.ArrayList;
import java.util.List;
class Example {
  void run(Statement sink, ServletRequest request) throws Exception {
    List<String> values = new ArrayList<>();
    values.add(request.getParameter("name"));
    values.add("one");
    values.add("two");
    values.remove(1);
    sink.execute("SELECT " + values.get(INDEX));
  }
}
"""
        proven = self.probe(source.replace("INDEX", "1"), (SERVLET_JAR,))
        self.assertEqual(proven["status"], "constant_sql_text")
        self.assertIn({"file_id": "F0", "line": 11, "role": "collection_remove"}, proven["evidence"])
        unknown_input = self.probe(source.replace("INDEX", "0"), (SERVLET_JAR,))
        self.assertEqual(unknown_input["status"], "external_input_contributes")
        self.assertIn({"file_id": "F0", "line": 8, "role": "servlet_request_read"}, unknown_input["evidence"])

    def test_collection_alias_or_object_remove_keeps_value_unknown(self):
        source = """import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
class Example {
  void run(Statement sink, String outside) throws Exception {
    List<String> values = new ArrayList<>();
    values.add("fixed");
    values.add(outside);
    CHANGE
    sink.execute("SELECT " + values.get(0));
  }
}
"""
        for change in ('List<String> alias = values; alias.set(0, outside);', 'values.remove("fixed");'):
            with self.subTest(change=change):
                self.assertEqual(self.probe(source.replace("CHANGE", change))["status"], "unknown")

    def test_map_reads_the_exact_key_and_forgets_state_after_unknown_key_write(self):
        source = """import java.sql.Statement;
import java.util.HashMap;
class Example {
  void run(Statement sink, String key, String input) throws Exception {
    sink.execute("SELECT " + lookup(key, input));
  }
  static String lookup(String key, String input) {
    var values = new HashMap<String, Object>();
    values.put("fixed", "first");
    values.put(SECOND_KEY, input);
    String value = (String) values.get("other");
    value = (String) values.get("fixed");
    return value;
  }
}
"""
        proven = self.probe(source.replace("SECOND_KEY", '"other"'))
        self.assertEqual(proven["status"], "constant_sql_text")
        self.assertIn({"file_id": "F0", "line": 12, "role": "collection_read"}, proven["evidence"])
        self.assertEqual(self.probe(source.replace("SECOND_KEY", "key"))["status"], "unknown")

    def test_unknown_condition_can_join_fixed_strings_after_a_loop(self):
        source = """import java.sql.Statement;
class Example {
  void run(Statement sink, boolean active, String input) throws Exception {
    String source = "before";
    while (active) {
      source = input;
      active = false;
    }
    String value = "first";
    if (source != null) value = SELECTED;
    sink.execute("SELECT " + value);
  }
}
"""
        proven = self.probe(source.replace("SELECTED", '"second"'))
        self.assertEqual(proven["status"], "fixed_sql_alternatives")
        self.assertIn({"file_id": "F0", "line": 10, "role": "fixed_values_from_branches"}, proven["evidence"])
        self.assertIn({"file_id": "F0", "line": 5, "role": "loop_local_values_invalidated"}, proven["evidence"])
        self.assertEqual(self.probe(source.replace("SELECTED", "source"))["status"], "unknown")

    def test_excludes_an_early_return_only_when_tracing_to_a_call(self):
        traced = self.probe("""import java.sql.Statement;
class Example {
  void run(Statement sink, boolean leave) throws Exception {
    if (leave) return;
    sink.execute("SELECT 1");
  }
}
""")
        self.assertEqual(traced["status"], "constant_sql_text")
        self.assertIn({"file_id": "F0", "line": 4, "role": "return_branch_excluded"}, traced["evidence"])
        helper = self.probe("""import java.sql.Statement;
class Example {
  void run(Statement sink, boolean choose, String input) throws Exception {
    sink.execute(value(choose, input));
  }
  static String value(boolean choose, String input) {
    if (choose) return input;
    return "SELECT 1";
  }
}
""")
        self.assertEqual(helper["status"], "unknown")

    @unittest.skipUnless(SERVLET_JAR.is_file(), "Servlet library is unavailable")
    def test_servlet_read_in_the_caller_keeps_its_file_coordinate(self):
        source = """import java.sql.Statement;
class Example {
  static void run(Statement sink, String value) throws Exception {
    sink.execute("SELECT " + value);
  }
}
"""
        caller = """import java.sql.Statement;
import javax.servlet.ServletRequest;
class Caller {
  void run(Statement sink, ServletRequest input) throws Exception {
    Example.run(sink, input.getParameter("field"));
  }
}
"""
        item = SimpleNamespace(start=4, end=4)
        bundle = {"files": {
            "F0": {"kind": "JAVA", "path": "Example.java", "masked_source": source},
            "F1": {"kind": "JAVA", "path": "Caller.java", "masked_source": caller},
        }, "snapshot_callers": ["F1"]}
        with tempfile.TemporaryDirectory() as directory:
            result = infer_specifications(item, bundle, {}, [{"path": str(SERVLET_JAR)}],
                                          Path(directory) / "java.log", value_evidence=True)
        argument, = result["jdbc_value_evidence"]["arguments"]
        self.assertEqual(argument["status"], "external_input_contributes")
        read, = result["sources"]
        self.assertEqual((read["file_id"], read["line"], read["role"]), ("F1", 5, "servlet_request_read"))

    def test_fallthrough_uses_the_last_assignment_on_selected_path(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void execute(Statement sink, String outside) throws Exception {
    String value = select(outside);
    sink.execute("SELECT " + value);
  }
  private static String select(String input) {
    String marker = "XYZ";
    String result = input;
    switch (marker.charAt(1)) {
      case 'Y': result = input;
      case 'Z': result = "static"; break;
      default: result = input;
    }
    return result;
  }
}
""")
        self.assertEqual(result["status"], "constant_sql_text")
        roles = {fact["role"]: fact["line"] for fact in result["evidence"]}
        self.assertEqual(roles["switch_case_selected"], 11)
        self.assertEqual(roles["switch_fallthrough"], 12)
        self.assertEqual(roles["helper_return"], 15)

    def test_jdbc_inside_switch_tracks_fallthrough_to_target(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void run(Statement sink, String outside) throws Exception {
    String sql = outside;
    switch (1) {
      case 1:
        sql = "SELECT 1";
      case 2:
        sink.execute(sql);
        break;
    }
  }
}
""")
        self.assertEqual(result["status"], "constant_sql_text")
        roles = {fact["role"]: fact["line"] for fact in result["evidence"]}
        self.assertEqual(roles["switch_case_selected"], 6)
        self.assertEqual(roles["switch_fallthrough"], 8)

    def test_jdbc_in_unselected_case_is_not_reported_as_a_value_proof(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void run(Statement sink) throws Exception {
    switch (1) {
      case 1: break;
      case 2: sink.execute("SELECT 1");
    }
  }
}
""")
        self.assertEqual(result["status"], "unknown")
        self.assertIn({"file_id": "F0", "line": 4, "role": "switch_target_not_reached"}, result["evidence"])

    def test_if_and_default_are_resolved_across_distinct_helper_calls(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void execute(Statement sink, String runtime) throws Exception {
    String sql = "SELECT " + fixed(9, runtime);
    sink.execute(sql);
  }
  static String fixed(int code, String userValue) {
    if (code == 2) return userValue;
    switch (code) {
      case 3 -> { return userValue; }
      default -> { return "fixed"; }
    }
  }
}
""")
        self.assertEqual(result["status"], "constant_sql_text")
        self.assertIn({"file_id": "F0", "line": 11, "role": "switch_case_selected"}, result["evidence"])

    def test_runtime_selector_remains_unknown(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void execute(Statement sink, int mode, String userValue) throws Exception {
    String value = select(mode, userValue);
    sink.execute("SELECT " + value);
  }
  static String select(int mode, String userValue) {
    switch (mode) {
      case 1: return "fixed";
      default: return userValue;
    }
  }
}
""")
        self.assertEqual(result["status"], "unknown")
        self.assertIn({"file_id": "F0", "line": 8, "role": "runtime_switch_selector"}, result["evidence"])
        self.assertIn("string_concatenation_with_unresolved_operand", {fact["role"] for fact in result["evidence"]})

    @unittest.skipUnless(SERVLET_JAR.is_file(), "Servlet library is unavailable")
    def test_selected_branch_can_preserve_external_input(self):
        result = self.probe("""import java.sql.Statement;
import javax.servlet.ServletRequest;
class Example {
  void execute(Statement sink, ServletRequest request) throws Exception {
    String value = select(true, request.getParameter("field"));
    sink.execute("SELECT " + value);
  }
  private static String select(boolean keep, String candidate) {
    if (keep) return candidate;
    return "fixed";
  }
}
""", (SERVLET_JAR,))
        self.assertEqual(result["status"], "external_input_contributes")
        roles = {fact["role"]: fact["line"] for fact in result["evidence"]}
        self.assertEqual(roles["servlet_request_read"], 5)
        self.assertEqual(roles["if_true"], 9)
        self.assertEqual(roles["helper_return"], 9)

    def test_runtime_assignment_does_not_keep_stale_constant(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void execute(Statement sink, boolean condition, String userValue) throws Exception {
    String sql = "SELECT 1";
    if (condition) sql = userValue;
    sink.execute(sql);
  }
}
""")
        self.assertEqual(result["status"], "unknown")

    def test_jdbc_result_assigned_to_local_inside_try_preserves_helper_proof(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void execute(Statement sink) throws Exception {
    String sql = query();
    boolean result;
    try {
      result = sink.execute(sql);
    } catch (java.sql.SQLException failure) {
      throw failure;
    }
  }
  private static String query() {
    return "SELECT 1";
  }
}
""")
        self.assertEqual(result["status"], "constant_sql_text")
        self.assertIn({"file_id": "F0", "line": 13, "role": "helper_return"}, result["evidence"])

    def test_assignment_to_field_stays_outside_the_local_jdbc_rule(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  boolean result;
  void execute(Statement sink) throws Exception {
    result = sink.execute("SELECT 1");
  }
}
""")
        self.assertEqual(result["status"], "unknown")
        self.assertIn({"file_id": "F0", "line": 5, "role": "scope_before_call_not_modeled"}, result["evidence"])

    def test_integer_condition_uses_java_signed_division_and_remainder(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void execute(Statement sink, String runtime) throws Exception {
    int base = -11;
    int total = (base / 3) * 2 + base % 3;
    String chosen = total <= -8 ? "fixed" : runtime;
    sink.execute("SELECT " + chosen);
  }
}
""")
        self.assertEqual(result["status"], "constant_sql_text")
        facts = {(item["line"], item["role"]) for item in result["evidence"]}
        self.assertIn((5, "integer_arithmetic"), facts)
        self.assertIn((6, "integer_comparison"), facts)

    def test_int_overflow_selects_the_java_branch(self):
        result = self.probe("""import java.sql.Statement;
class Example {
  void execute(Statement sink, String runtime) throws Exception {
    int ceiling = Integer.MAX_VALUE;
    int total = ceiling + 1;
    String chosen;
    if (total < 0) chosen = "fixed";
    else chosen = runtime;
    sink.execute("SELECT " + chosen);
  }
}
""")
        self.assertEqual(result["status"], "constant_sql_text")
        self.assertIn((7, "if_true"), {(item["line"],item["role"]) for item in result["evidence"]})

    @unittest.skipUnless(SERVLET_JAR.is_file(), "Servlet library is unavailable")
    def test_integer_condition_can_preserve_request_data(self):
        result = self.probe("""import java.sql.Statement;
import javax.servlet.ServletRequest;
class Example {
  void execute(Statement sink, ServletRequest request) throws Exception {
    int difference = 17 - 12;
    String chosen = difference >= 6 ? "fixed" : request.getParameter("field");
    sink.execute("SELECT " + chosen);
  }
}
""", (SERVLET_JAR,))
        self.assertEqual(result["status"], "external_input_contributes")
        facts = {item["role"] for item in result["evidence"]}
        self.assertTrue({"integer_comparison", "conditional_value_selected", "servlet_request_read"} <= facts)

    def test_runtime_operand_and_division_by_zero_remain_unknown(self):
        for numerator, denominator in [("runtime", "2"), ("8", "zero")]:
            with self.subTest(numerator=numerator, denominator=denominator):
                result = self.probe(f"""import java.sql.Statement;
class Example {{
  void execute(Statement sink, int runtime, String supplied) throws Exception {{
    int zero = 0;
    int ratio = {numerator} / {denominator};
    String chosen = ratio > 3 ? "fixed" : supplied;
    sink.execute("SELECT " + chosen);
  }}
}}
""")
                self.assertEqual(result["status"], "unknown")
