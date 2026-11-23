import contextlib
import io
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MAIN = runpy.run_path(str(ROOT / "scripts" / "ai_sec.py"))["main"]


class WorkflowLauncherTests(unittest.TestCase):
    @patch("os.execv")
    @patch("os.chdir")
    def test_analysis_passes_collection_and_check_to_legacy_router(self, chdir, execv):
        args = ["--from-run", "runs/collection", "--check", "--only-component", "project:Example.java"]
        MAIN(["analyze", *args])
        chdir.assert_called_once_with(ROOT)
        execv.assert_called_once_with(sys.executable, [sys.executable, "master_pipeline_multi_v1.py", *args])

    @patch("os.execv")
    @patch("os.chdir")
    def test_review_uses_directory_where_flask_imports_resolve(self, chdir, execv):
        MAIN(["review", "--help"])
        chdir.assert_called_once_with(ROOT / "review_ui")
        execv.assert_called_once_with(sys.executable, [
            sys.executable, "-m", "flask", "--app", "app", "run",
            "--host", "127.0.0.1", "--port", "5050", "--help",
        ])

    @patch("os.execv")
    @patch("os.chdir")
    def test_invalid_workflow_never_runs_a_child(self, chdir, execv):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            MAIN(["invalid"])
        self.assertEqual(error.exception.code, 2)
        chdir.assert_not_called()
        execv.assert_not_called()
