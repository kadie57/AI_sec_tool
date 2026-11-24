from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

from sql_pipeline.evidence.sql_endpoint_specifications import infer_specifications


SERVLET_JAR = Path.home() / ".m2/repository/javax/javaee-api/8.0.1/javaee-api-8.0.1.jar"


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "A full JDK is required")
class SqlJdbcValueEvidenceTest(unittest.TestCase):
    def probe(self, source, dependencies=()):
        alert, = (n for n, line in enumerate(source.splitlines(), 1) if "sink.execute(" in line)
        item = SimpleNamespace(start=alert, end=alert)
        bundle = {"files": {"F0": {"kind": "JAVA", "path": "Example.java", "masked_source": source}}}
        deps = [{"path": str(jar)} for jar in dependencies]
        with tempfile.TemporaryDirectory() as directory:
            result = infer_specifications(item, bundle, {}, deps, Path(directory) / "java.log", value_evidence=True)
        self.assertEqual(result["sink_resolution"], "one_verified_signature")
        argument, = result["jdbc_value_evidence"]["arguments"]
        self.assertEqual(argument["call"]["line"], alert)
        return argument

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
