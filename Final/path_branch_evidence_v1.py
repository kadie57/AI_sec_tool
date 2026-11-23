"""Supplementary bounded Java expression facts. Does not assign TP/FP labels."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

VERSION = "java-local-branch-evidence-v1"


def tool_hashes():
    root = Path(__file__).resolve().parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("path_branch_evidence_v1.py", "PathBranchEvidence.java")}


def collect(source):
    helper = Path(__file__).resolve().with_name("PathBranchEvidence.java")
    with tempfile.TemporaryDirectory(prefix="path-branch-audit-") as tmp:
        path = Path(tmp) / "Input.java"
        path.write_text(source, encoding="utf-8")
        proc = subprocess.run(["java", str(helper), str(path)],
                              capture_output=True, text=True, timeout=60)
    if proc.returncode:
        raise ValueError("Không chạy được bộ đọc Java; cần JDK 17+. Chi tiết: " + proc.stderr[-1800:])
    data = json.loads(proc.stdout)
    if data.get("version") != VERSION or data.get("status") != "PARSED_PARTIAL" or not isinstance(data.get("facts"), list):
        raise ValueError("Kết quả tính điều kiện Java không hợp lệ.")
    for fact in data["facts"]:
        lines = [fact["line"], *fact["dependency_lines"]]
        if any(type(n) is not int or not 1 <= n <= len(source.splitlines()) for n in lines):
            raise ValueError("Dòng bằng chứng điều kiện không khớp nguồn.")
        if type(fact["condition_value"]) is not bool:
            raise ValueError("Kết quả điều kiện không phải boolean.")
    data.update(source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
                tool_hashes=tool_hashes(),
                limitations=["Parses Java; does not execute or type-check the input program.",
                             "Local int/boolean straight-line expressions only; unknown control-flow writes invalidate values.",
                             "Selected expression is a fact at that line only, not proof of value reaching a sink.",
                             "No vulnerability label or filesystem safety conclusion."])
    return data


def check_runtime():
    sample = 'class Check { void f() { int limit=3; String s = limit*2>5 ? "fixed" : "other"; } }'
    data = collect(sample)
    if len(data["facts"]) != 1 or data["facts"][0].get("selected_string_literal") != "fixed":
        raise ValueError("Bộ tính điều kiện Java chưa hoạt động đúng.")
    return True
