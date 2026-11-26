from importlib import import_module
from pathlib import Path
from shutil import copytree, ignore_patterns
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class LegacyEntryPointsTest(unittest.TestCase):
    def test_legacy_imports_share_the_current_implementations(self):
        aliases = {
            "sql_pipeline.cwe_mapper": "common.cwe_mapper",
            "sql_pipeline.run_io": "common.run_io",
            "sql_pipeline.evidence.source_text": "common.source_text",
            "sql_pipeline.evidence.sql_endpoint_specifications": "analyzers.sql_injection.evidence.sql_endpoint_specifications",
        }
        for legacy, current in aliases.items():
            with self.subTest(legacy=legacy):
                self.assertIs(import_module(legacy), import_module(current))

    def test_java_probe_sources_are_available_next_to_the_analyzer(self):
        module = import_module("analyzers.sql_injection.evidence.sql_endpoint_specifications")
        directory = Path(module.__file__).parent
        for probe in (module.PROBE, module.VALUE_PROBE):
            self.assertEqual(probe.parent, directory)
            self.assertTrue(probe.is_file())

    def test_current_module_commands_work_without_legacy_entry_points(self):
        project = Path(__file__).resolve().parents[1]
        modules = (
            "common.sonar_collection",
            "analyzers.sql_injection.prepare_sql_evidence",
            "analyzers.sql_injection.sql_llm_experiment",
            "analyzers.sql_injection.sql_project_flow_experiment",
            "analyzers.sql_injection.sql_source_spec_experiment",
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for package in ("analyzers", "common"):
                copytree(project / package, root / package, ignore=ignore_patterns("__pycache__"))
            for module in modules:
                with self.subTest(module=module):
                    result = subprocess.run(
                        [sys.executable, "-B", "-E", "-m", module, "--help"],
                        cwd=root, capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("usage:", result.stdout)
