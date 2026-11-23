"""Launch an existing AI_sec_tool workflow from the checkout it belongs to."""

import argparse
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {
    "collect": (".", ("master_pipeline.py", "--collect-only")),
    "analyze": (".", ("master_pipeline_multi_v1.py",)),
    "review": ("review_ui", ("-m", "flask", "--app", "app", "run",
                            "--host", "127.0.0.1", "--port", "5050")),
    "owasp-plan": (".", ("prepare_owasp_holdout.py",)),
    "owasp-collect": (".", ("collect_owasp_holdout.py",)),
    "owasp-analyze": (".", ("run_holdout_system.py",)),
    "owasp-compat": (".", ("owasp_compat_v1.py",)),
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run a workflow using the legacy entry point and its working directory.",
        epilog="Arguments after the workflow name are passed to its entry point.",
    )
    parser.add_argument("workflow", choices=COMMANDS)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    directory, command = COMMANDS[args.workflow]
    os.chdir(ROOT / directory)
    os.execv(sys.executable, [sys.executable, *command, *args.arguments])


if __name__ == "__main__":
    main()
