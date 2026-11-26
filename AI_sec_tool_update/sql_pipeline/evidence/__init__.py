"""Compatibility imports for the original SQL evidence modules."""

from importlib import import_module
import sys

from common import source_text

sys.modules[f"{__name__}.source_text"] = source_text

for name in (
    "joern_sql", "sql_context_bundle_v1", "sql_endpoint_specifications", "sql_evidence_selection",
    "sql_path_presentation", "sql_project_paths", "sql_review_consistency", "sql_snapshot_callers", "sql_source_paths",
):
    module = import_module(f"analyzers.sql_injection.evidence.{name}")
    sys.modules[f"{__name__}.{name}"] = module
    globals()[name] = module
