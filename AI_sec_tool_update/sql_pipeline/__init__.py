"""Compatibility imports for the original SQL warning review package."""

import sys

from common import cwe_mapper, run_io

sys.modules[f"{__name__}.cwe_mapper"] = cwe_mapper
sys.modules[f"{__name__}.run_io"] = run_io
