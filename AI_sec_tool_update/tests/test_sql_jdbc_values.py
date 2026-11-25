from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

from sql_pipeline.evidence.sql_endpoint_specifications import infer_specifications


SERVLET_JAR = Path.home() / ".m2/repository/javax/javaee-api/8.0.1/javaee-api-8.0.1.jar"


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "A full JDK is required")
class SqlJdbcValueEvidenceTest(unittest.TestCase):
    def probe(self, source, dependencies=(), caller=None):
        alert, = (n for n, line in enumerate(source.splitlines(), 1) if "sink.execute(" in line)
        item = SimpleNamespace(start=alert, end=alert)
        bundle = {"files": {"F0": {"kind": "JAVA", "path": "Example.java", "masked_source": source}}}
        if caller is not None:
            bundle["files"]["F1"] = {"kind": "JAVA", "path": "Caller.java", "masked_source": caller}
            bundle["snapshot_callers"] = ["F1"]
        deps = [{"path": str(jar)} for jar in dependencies]
        with tempfile.TemporaryDirectory() as directory:
            result = infer_specifications(item, bundle, {}, deps, Path(directory) / "java.log", value_evidence=True)
        self.assertEqual(result["sink_resolution"], "one_verified_signature")
        argument, = result["jdbc_value_evidence"]["arguments"]
        self.assertEqual(argument["call"]["line"], alert)
        return argument

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
