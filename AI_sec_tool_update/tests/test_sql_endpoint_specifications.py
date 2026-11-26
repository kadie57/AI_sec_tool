import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sql_pipeline.cwe_mapper import get_cwe_info
from sql_pipeline.evidence.sql_endpoint_specifications import infer_specifications


SPRING_JARS = tuple(
    Path.home() / f".m2/repository/org/springframework/spring-{module}/5.3.39/spring-{module}-5.3.39.jar"
    for module in ("jdbc", "beans", "core", "jcl", "tx")
)


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "A full JDK is required")
class SqlEndpointSpecificationsTest(unittest.TestCase):
    def probe(self, source, line, dependencies=(), *, value_evidence=False):
        bundle = {"files": {"F0": {"kind": "JAVA", "path": "Example.java", "masked_source": source}}}
        item = SimpleNamespace(start=line, end=line)
        with tempfile.TemporaryDirectory() as directory:
            return infer_specifications(item, bundle, {}, [{"path": str(path)} for path in dependencies],
                                        Path(directory) / "java.log", value_evidence=value_evidence)

    def test_resolves_multiline_sql_and_associates_only_same_statement(self):
        source = """import java.sql.*;
class Example {
  void method(Connection connection, PreparedStatement unrelated) throws SQLException {
    PreparedStatement statement = connection.prepareStatement(
        "SELECT 1");
    unrelated.setString(1, "other");
    statement.setString(1, "value");
  }
}
"""
        result = self.probe(source, line=4)
        self.assertEqual(result["sink_resolution"], "one_verified_signature")
        sink = result["sinks"][0]
        self.assertEqual(sink["signature"], "prepareStatement(java.lang.String)")
        self.assertEqual(sink["argument"], {"file_id": "F0", "line": 5})
        (binding,) = sink["bindings"]
        self.assertEqual(binding["line"], 7)
        self.assertEqual(binding["argument_index"], 2)

    def test_excludes_same_named_local_apis(self):
        source = """class Example {
  static class Local {
    void execute(String text) {}
    String getHeader(String key) { return key; }
  }
  void method(Local local) {
    local.execute(local.getHeader("key"));
  }
}
"""
        result = self.probe(source, line=7)
        self.assertEqual(result["analysis"], "resolved_symbols")
        self.assertEqual(result["sink_resolution"], "unresolved")
        self.assertEqual(result["sources"], [])

    def test_does_not_associate_a_reassigned_receiver(self):
        source = """import java.sql.*;
class Example {
  void method(Connection connection, PreparedStatement other) throws SQLException {
    PreparedStatement statement = connection.prepareStatement("SELECT 1");
    statement = other;
    statement.setString(1, "value");
  }
}
"""
        result = self.probe(source, line=4)
        self.assertEqual(result["sink_resolution"], "one_verified_signature")
        self.assertEqual(result["sinks"][0]["bindings"], [])

    @unittest.skipUnless(all(path.is_file() for path in SPRING_JARS), "Spring JDBC benchmark jars are required")
    def test_spring_varargs_keep_result_type_separate_from_bindings(self):
        result = self.probe("""import org.springframework.jdbc.core.JdbcOperations;
class Example {
  void method(JdbcOperations template, String value) {
    template.queryForObject(
        "SELECT id FROM example WHERE label = ? AND flag = ?", String.class,
        value, true);
  }
}
""", 4, SPRING_JARS, value_evidence=True)
        self.assertEqual(result["sink_resolution"], "one_verified_signature")
        sink, = result["sinks"]
        self.assertEqual(sink["owner"], "org.springframework.jdbc.core.JdbcOperations")
        self.assertEqual(sink["argument"], {"file_id": "F0", "line": 5})
        self.assertEqual([binding["argument_index"] for binding in sink["bindings"]], [3, 4])
        argument, = result["jdbc_value_evidence"]["arguments"]
        self.assertEqual(argument["status"], "constant_sql_text")

    @unittest.skipUnless(all(path.is_file() for path in SPRING_JARS), "Spring JDBC benchmark jars are required")
    def test_spring_explicit_array_is_bound_and_creator_is_not_sql_text(self):
        source = """import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
class Example {
  void method(JdbcTemplate template, String value, PreparedStatementCreator creator) {
    template.queryForObject("SELECT ?", new Object[]{value}, new int[]{12}, String.class);
    template.query(creator, (rs, index) -> rs.getString(1));
  }
}
"""
        explicit = self.probe(source, 5, SPRING_JARS)
        sink, = explicit["sinks"]
        binding, = sink["bindings"]
        self.assertEqual(binding["argument_index"], 2)
        self.assertEqual(self.probe(source, 6, SPRING_JARS)["sink_resolution"], "unresolved")

    def test_maps_spring_plugin_and_native_security_rules(self):
        for rule in ("findsecbugs:SQL_INJECTION_SPRING_JDBC", "findbugs:SQL_INJECTION_SPRING_JDBC",
                     "javasecurity:S3649"):
            with self.subTest(rule=rule):
                mapped = get_cwe_info(rule)
                self.assertEqual(mapped["cwe_id"], "CWE-89")
                self.assertTrue(mapped["supported"])

    @unittest.skipUnless(all(path.is_file() for path in SPRING_JARS), "Spring JDBC benchmark jars are required")
    def test_spring_batch_targets_one_sql_string_without_treating_it_as_binding(self):
        source = """import org.springframework.jdbc.core.JdbcTemplate;
class Example {
  void method(JdbcTemplate template, String[] statements) {
    template.batchUpdate("DELETE FROM demo");
    template.batchUpdate("DELETE FROM demo", "DELETE FROM staging");
    template.batchUpdate(statements);
  }
}
"""
        result = self.probe(source, 4, SPRING_JARS, value_evidence=True)
        sink, = result["sinks"]
        self.assertEqual(sink["bindings"], [])
        self.assertEqual(result["jdbc_value_evidence"]["arguments"][0]["status"], "constant_sql_text")
        for line in (5, 6):
            with self.subTest(line=line):
                self.assertEqual(self.probe(source, line, SPRING_JARS)["sink_resolution"], "unresolved")
