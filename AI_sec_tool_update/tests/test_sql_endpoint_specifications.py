import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sql_pipeline.evidence.sql_endpoint_specifications import infer_specifications


@unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "A full JDK is required")
class SqlEndpointSpecificationsTest(unittest.TestCase):
    def probe(self, source, line):
        bundle = {"files": {"F0": {"kind": "JAVA", "path": "Example.java", "masked_source": source}}}
        item = SimpleNamespace(start=line, end=line)
        with tempfile.TemporaryDirectory() as directory:
            return infer_specifications(item, bundle, {}, [], Path(directory) / "java.log")

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
