"""Read saved predictions and reconstruct the evidence shown in each request."""

from collections import Counter
import json
from pathlib import Path
import re

from common.ollama_review import VERDICTS, digest

CATEGORIES = {"CWE-89": "SQL Injection", "CWE-22": "Path Traversal"}
RUN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
NUMBERED_LINE = re.compile(r"(F\d+):([1-9]\d*)(?: (.*))?")
OUTCOMES = {"TP": "Cảnh báo đúng, Qwen giữ", "TN": "Cảnh báo nhầm, Qwen loại",
            "FP": "Cảnh báo nhầm, Qwen giữ", "FN": "Cảnh báo đúng, Qwen loại"}


def artifact(directory, *parts):
    """Only read regular files inside the chosen run."""
    try:
        path = directory.joinpath(*parts).resolve()
        if path.is_relative_to(directory) and path.is_file():
            return path
    except (OSError, RuntimeError):
        pass


def read_object(path):
    if path is None:
        return {}
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError):
        return {}


def run_info(root, name):
    if not RUN_NAME.fullmatch(name):
        return None
    directory = root / name
    if directory.is_symlink() or not directory.is_dir():
        return None
    manifest_path = artifact(directory, "llm", "manifest.json")
    manifest = read_object(manifest_path)
    cases = manifest.get("cases")
    if manifest.get("mode") != "ollama" or not isinstance(cases, list) or not cases:
        return None
    keys = set()
    categories = set()
    for item in cases:
        if not isinstance(item, dict) or not isinstance(item.get("alert"), dict):
            return None
        key, alert = item.get("issue_id"), item["alert"]
        if not isinstance(key, str) or key in keys:
            return None
        cwe = alert.get("cwe")
        if cwe not in CATEGORIES:
            return None
        keys.add(key)
        categories.add(cwe)
    if len(categories) != 1:
        return None
    cwe = categories.pop()
    return {
        "name": name, "directory": directory, "cwe": cwe, "category": CATEGORIES[cwe],
        "updated": manifest_path.stat().st_mtime, "manifest": manifest,
        "total": len(cases),
        "saved": sum(path is not None for _, _, path in case_files(directory, cases)),
    }


def list_runs(root):
    if not root.is_dir():
        return []
    return sorted(
        (run for path in root.iterdir() if (run := run_info(root, path.name))),
        key=lambda run: (run["updated"], run["name"]), reverse=True,
    )


def case_files(directory, items, folder="llm"):
    for number, item in enumerate(items, 1):
        yield number, item, artifact(directory, folder, f"case-{number:04d}.json")


def matching_request(result, item):
    request = result.get("request")
    return (
        isinstance(request, dict)
        and result.get("issue_id") == item["issue_id"]
        and digest(request) == item.get("request_sha256")
    )


def reference_rows(directory, summary):
    report = read_object(artifact(directory, "cases.json"))
    rows = [*(summary.get("cases") or []), *(summary.get("changed_cases") or []),
            *(report.get("warnings") or [])]
    return {row["issue_id"]: row for row in rows
            if isinstance(row, dict) and isinstance(row.get("issue_id"), str)
            and type(row.get("reference_vulnerability")) is bool}


def load_cases(run):
    directory = run["directory"]
    summary = read_object(artifact(directory, "summary.json"))
    references = reference_rows(directory, summary)
    cases = []
    for number, item, path in case_files(directory, run["manifest"]["cases"]):
        result = read_object(path)
        valid_request = matching_request(result, item)
        assessment = {}
        if path is None:
            status = "pending"
        elif not valid_request or result.get("error"):
            status = "error"
        else:
            assessment = result.get("assessment") or {}
            status = assessment.get("verdict")
            if status not in VERDICTS:
                status, assessment = "error", {}
        alert = item["alert"]
        component = alert.get("component", "")
        ref = references.get(item["issue_id"], {})
        reference = ref.get("reference_vulnerability")
        if ref.get("request_sha256") not in (None, item.get("request_sha256")):
            reference = None
        outcome = None
        if reference is not None and status in {"LIKELY_TP", "LIKELY_FP"}:
            keep = status == "LIKELY_TP"
            outcome = ("T" if keep == reference else "F") + ("P" if keep else "N")
        cases.append({
            "number": number, "item": item, "alert": alert, "key": item["issue_id"],
            "file": component.split(":", 1)[-1], "name": Path(component).name.split(":")[-1],
            "status": status, "assessment": assessment, "reference": reference,
            "outcome": outcome, "outcome_label": OUTCOMES.get(outcome),
            "result": result if valid_request else {},
        })
    return cases, summary


def warning_scope(run):
    return {item["issue_id"]: (item["alert"], item.get("source"))
            for item in run["manifest"]["cases"]}


def totals(cases, summary):
    counts = Counter(case["status"] for case in cases)
    graded = sum(case["reference"] is not None for case in cases)
    correct = sum(case["outcome"] in {"TP", "TN"} for case in cases) if graded else None
    qwen = summary.get("qwen") or summary.get("after") or {}
    if qwen.get("warnings", len(cases)) == len(cases) and type(qwen.get("correct")) is int:
        correct = qwen["correct"]
    return {
        "counts": counts, "answered": sum(counts[v] for v in VERDICTS),
        "correct": correct, "reference_count": graded, "saved": len(cases) - counts["pending"],
    }


def prompt_for(run, case):
    result = case["result"]
    if not result and case["status"] == "pending":
        name = f"case-{case['number']:04d}.json"
        dry_run = read_object(artifact(run["directory"], "dry-run", name))
        if matching_request(dry_run, case["item"]):
            result = dry_run
    try:
        prompt = json.loads(result["request"]["prompt"])
    except (KeyError, TypeError, ValueError):
        return {}
    return prompt if isinstance(prompt, dict) else {}


def sql_excerpts(value):
    """Find numbered source snippets in the SQL evidence sections."""
    if isinstance(value, str):
        match = NUMBERED_LINE.fullmatch(value)
        if match and match[3]:
            yield match[1], int(match[2]), match[3]
    elif isinstance(value, dict):
        file_id, line, code = value.get("file_id"), value.get("line"), value.get("code")
        if isinstance(file_id, str) and type(line) is int and isinstance(code, str):
            yield file_id, line, code
        for child in value.values():
            yield from sql_excerpts(child)
    elif isinstance(value, list):
        for child in value:
            yield from sql_excerpts(child)


def request_sources(prompt):
    excerpts = {}
    for file_id, line, code in sql_excerpts(prompt.get("selected_evidence", {})):
        excerpts.setdefault(file_id, {}).setdefault(line, code)
    sources = []
    for file in prompt.get("files", []):
        file_id = file.get("file_id", "")
        if not re.fullmatch(r"F\d+", file_id):
            continue
        lines = excerpts.get(file_id, {}).copy()
        lines.update({n: code for n, code in enumerate(file.get("lines", []), 1) if code.strip()})
        lines.update({n: code for fid, n, code in sql_excerpts(file.get("numbered_source", "").splitlines())
                      if fid == file_id})
        sources.append({"id": file_id, "path": file.get("path", ""), "lines": sorted(lines.items())})
    return sources


def sql_location(node):
    if isinstance(node, str):
        node = {"code": node}
    text = node.get("anchor") or node.get("code")
    match = NUMBERED_LINE.fullmatch(text) if isinstance(text, str) else None
    return {
        "file_id": match[1] if match else None,
        "line": int(match[2]) if match else None,
        "label": node.get("verified_api") or node.get("method") or node.get("node_kind"),
    }


def sql_path(path):
    if "source_line" in path:
        lines = [path["source_line"], *path.get("intermediate_lines", []), path.get("sql_argument_line")]
        return [{"file_id": "F0", "line": n} for n in lines]
    nodes = [path.get("Source") or {}, *path.get("Steps", []), path.get("Sink") or {}]
    return [sql_location(node) for node in nodes]


def evidence_view(prompt):
    """Keep candidate paths and Java findings in separate sections."""
    flow = prompt.get("project_flow") or {}
    selected = prompt.get("selected_evidence") or {}
    groups = []
    facts = []
    for operation in flow.get("operations", []):
        target = operation["target"]
        groups.append({
            "title": ".".join(filter(None, (target.get("owner"), target.get("method")))),
            "target": target, "role": target.get("role"), "status": operation.get("status"),
            "paths": [[path["source"], *path.get("steps", []), target] for path in operation.get("paths", [])],
            "limited": operation.get("search_limit_hit"),
        })
        if proof := target.get("java_operand_value"):
            steps = [*proof.get("steps", []),
                     *proof.get("resolved_helper_branches", {}).get("decisions", []),
                     *proof.get("request_input_branch", {}).get("input_steps", [])]
            facts.append({"title": proof.get("origin"), "text": proof.get("meaning"), "refs": steps})
    if paths := selected.get("paths"):
        groups.append({
            "title": "Đường đi tới đối số JDBC",
            "status": selected.get("path_status"),
            "paths": [sql_path(path) for path in paths],
            "limited": (selected.get("anchored_dataflow") or {}).get("search_limit_hit"),
        })
    if finding := selected.get("verified_alert_sink"):
        if isinstance(finding, dict):
            facts.append({"text": finding.get("verified_finding"), "refs": [
                *finding.get("selected_branch", []), *finding.get("value_to_jdbc", []),
                *finding.get("constant_context", []),
            ]})
        else:
            facts.append({"text": finding, "refs": []})
    if value := selected.get("anchored_dataflow", {}).get("modeled_sql_value"):
        facts.append({"title": value, "refs": []})
    for arg in selected.get("jdbc_value_evidence", {}).get("arguments", []):
        facts.append({"title": arg.get("status"), "refs": arg.get("evidence", [])})
    java = prompt.get("java_evidence") or {}
    for use in java.get("same_method_path_use", {}).get("uses", []):
        op = use["operation"]
        facts.append({
            "title": ".".join(filter(None, (op.get("owner"), op.get("method")))),
            "text": " · ".join(filter(None, (use.get("link"), use.get("origin")))),
            "refs": [{"file_id": "F0", "line": n} for n in use.get("evidence_lines", [])],
        })
    for anchor in java.get("anchors", []):
        facts.append({"title": ".".join(filter(None, (anchor.get("owner"), anchor.get("method")))),
                      "refs": [{"file_id": "F0", **anchor}]})
    return groups, facts
