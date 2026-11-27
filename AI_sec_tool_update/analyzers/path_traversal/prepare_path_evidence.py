"""Prepare a static CWE-22 baseline from saved SonarQube warnings."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from common.run_io import run_command, save_json
from common.sonar_artifacts import issue_range, resolve_issue_path
from common.source_text import mask_java


VERSION = "path-evidence-v2"
SUPPORTED_VERSIONS = {"path-evidence-v1", VERSION}
RULES = frozenset({"findbugs:PATH_TRAVERSAL_IN", "findsecbugs:PATH_TRAVERSAL_IN"})
PROBE = Path(__file__).with_name("evidence") / "PathEvidenceProbe.java"
LOCAL_FLOW = PROBE.with_name("PathLocalFlow.java")
FILE_OPERATIONS = {"file_read", "file_write", "file_io", "file_metadata"}
PATH_ROLES = {"path_construction", *FILE_OPERATIONS}
VALUE_ORIGINS = {
    "fixed_value", "configuration_value", "external_input_in_expression", "possible_external_input_in_expression",
    "unknown",
}
JVM_PARAMETER = re.compile(r"(\[*)(L[\w/$]+;|[ZBCSIJFD])")
JVM_PRIMITIVES = dict(zip("ZBCSIJFD", ("boolean", "byte", "char", "short", "int", "long", "float", "double")))


def load_collection(collection, source_root):
    documents = {name: (collection / name).read_bytes() for name in ("manifest.json", "issues.json")}
    manifest, findings = (json.loads(documents[name]) for name in documents)
    if manifest.get("state") not in {"COLLECTED", "COMPLETED"} or not manifest.get("analysis_id"):
        raise ValueError("A completed SonarQube collection with an analysis ID is required.")
    project, hashes = manifest["project"], manifest["source_hashes"]
    records = {}
    for issue in findings["issues"]:
        if issue["rule"] not in RULES:
            continue
        issue_id = issue["key"]
        if not issue_id or issue_id in records:
            raise ValueError("Missing or duplicate CWE-22 issue ID.")
        path = resolve_issue_path(issue, project, source_root)
        relative = path.relative_to(source_root).as_posix()
        raw = path.read_bytes()
        source_hash = sha256(raw).hexdigest()
        if hashes.get(relative) != source_hash:
            raise ValueError(f"Source differs from the SonarQube snapshot: {relative}")
        lines = mask_java(raw.decode("utf-8")).splitlines()
        start, end = issue_range(issue)
        if end > len(lines):
            raise ValueError(f"Warning coordinates exceed the source: {relative}")
        records[issue_id] = {
            "alert": {"issue_id": issue_id, "component": issue["component"], "rule": issue["rule"],
                      "cwe": "CWE-22", "start_line": start, "end_line": end},
            "source": {"file_id": "F0", "path": relative, "sha256": source_hash, "lines": lines},
            "scanner_api": scanner_api(issue.get("message", "")),
        }
    if not records:
        raise ValueError("No supported CWE-22 warnings in the collection.")
    return manifest, records, {name: sha256(raw).hexdigest() for name, raw in documents.items()}


def scanner_api(message):
    hint = re.search(r"This API \(([\w/$]+)\.([\w$<>]+)\(([^()]*)\)", message)
    if not hint:
        return None
    owner, method, descriptor = hint.groups()
    parameters = []
    position = 0
    while position < len(descriptor):
        parameter = JVM_PARAMETER.match(descriptor, position)
        if parameter is None:
            return None
        dimensions, base = parameter.groups()
        name = base[1:-1].replace("/", ".") if base.startswith("L") else JVM_PRIMITIVES[base]
        parameters.append(name + "[]" * len(dimensions))
        position = parameter.end()
    return {"owner": owner.replace("/", "."), "method": method, "parameters": parameters}


def decode_sites(output, line_count):
    header, *rows = output.splitlines()
    status, count = header.split("\t")
    if status != "STATUS" or not count.isdecimal():
        raise ValueError("Malformed Java probe status.")
    sites, uses = {}, []
    for row in rows:
        fields = row.split("\t")
        if fields[0] == "USE":
            _, operation_id, argument, origin, producers, lines, fixed_defs = fields
            uses.append((int(operation_id), int(argument), origin,
                         [int(item) for item in producers.split(",") if item],
                         [int(item) for item in lines.split(",") if item],
                         [int(item) for item in fixed_defs.split(",") if item]))
            continue
        kind, site_id, role, owner, method, parameters, start, end, first, last, method_start, method_end, arguments = fields
        site_id = int(site_id)
        start, end, first, last, method_start, method_end = map(int, (start, end, first, last, method_start, method_end))
        argument_lines = [int(line) for line in arguments.split(",")] if arguments else []
        if (kind != "SITE" or site_id < 1 or site_id in sites
                or not 1 <= method_start <= first <= start <= end <= last <= method_end <= line_count
                or any(not start <= line <= end for line in argument_lines)):
            raise ValueError("Java probe coordinates differ from the source snapshot.")
        sites[site_id] = {
            "role": role, "owner": owner, "method": method, "parameters": parameters.split(",") if parameters else [],
            "line": start, "end_line": end, "statement_start": first, "statement_end": last,
            "method_start": method_start, "method_end": method_end, "argument_lines": argument_lines,
        }
    for operation_id, argument, origin, producers, lines, fixed_defs in uses:
        operation = sites.get(operation_id)
        if (not operation or operation["role"] not in FILE_OPERATIONS or origin not in VALUE_ORIGINS
                or not 0 <= argument <= len(operation["argument_lines"])
                or (argument == 0 and operation["owner"] != "java.io.File")
                or any(producer not in sites for producer in producers)
                or any(not operation["method_start"] <= line <= operation["method_end"] for line in (*lines, *fixed_defs))):
            raise ValueError("Java path-use facts differ from the recorded API sites.")
    return int(count), sites, uses


def select_evidence(alert, reported, sites, uses):
    def in_warning(start, end):
        return start <= alert["end_line"] and end >= alert["start_line"]

    candidates = [(site_id, site) for site_id, site in sites.items() if site["role"] in PATH_ROLES and (
        reported is None or all(site[name] == value for name, value in reported.items())
    )]
    anchors = [(site_id, site) for site_id, site in candidates if in_warning(site["line"], site["end_line"])]
    if not anchors and reported:
        anchors = [(site_id, site) for site_id, site in candidates if in_warning(site["statement_start"], site["statement_end"])]
    methods = {(site["method_start"], site["method_end"]) for _, site in anchors}
    context = [site for site in sites.values() if (site["method_start"], site["method_end"]) in methods]
    result = {
        "anchor_status": {0: "unresolved", 1: "one_typed_api"}.get(len(anchors), "multiple_typed_apis"),
        "anchors": [site for _, site in anchors],
        "sites_in_anchor_methods": context,
    }
    if len(anchors) != 1:
        return result
    (anchor_id, _), = anchors
    linked = []
    for operation_id, argument, origin, producers, lines, fixed_defs in uses:
        if anchor_id != operation_id and anchor_id not in producers:
            continue
        operation = sites[operation_id]
        linked.append({
            "operation": {key: operation[key] for key in ("role", "owner", "method", "line")},
            "path_input": "receiver" if argument == 0 else f"argument_{argument}",
            "link": "warning_is_the_operation" if anchor_id == operation_id else "warning_value_reaches_the_operation",
            "origin": origin,
            "evidence_lines": lines,
            "fixed_component_definition_lines": fixed_defs,
        })
    if linked:
        result["same_method_path_use"] = {
            "scope": "Value trace on supported branches of one method. File metadata queries are separate from reading or writing contents. No directory-containment or exploitability conclusion.",
            "uses": linked,
        }
    return result


def export_evidence(collection, source_root, output, classpath=()):
    collection, source_root, output = (p.resolve() for p in (collection, source_root, output))
    if output.is_relative_to(collection) or output.is_relative_to(source_root):
        raise ValueError("Write evidence outside the input snapshot and collection.")
    manifest, rows, collection_hashes = load_collection(collection, source_root)
    jars = [path.resolve(strict=True) for path in classpath]
    if any(not path.is_file() or path.suffix != ".jar" or os.pathsep in str(path) for path in jars):
        raise ValueError("Java classpath entries must be local JAR files.")
    output.mkdir(parents=True, exist_ok=False)
    metadata = {"state": "IN_PROGRESS", "version": VERSION, "collection": str(collection),
                "analysis_id": manifest["analysis_id"], "project": manifest["project"],
                "collection_hashes": collection_hashes,
                "probe_sha256": sha256(PROBE.read_bytes()).hexdigest(),
                "local_flow_sha256": sha256(LOCAL_FLOW.read_bytes()).hexdigest(),
                "classpath": [{"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()} for path in jars],
                "scope": "One Java file per probe; typed API locations and bounded same-method path uses."}
    save_json(output / "manifest.json", metadata)
    cache = {}
    try:
        with TemporaryDirectory(prefix="path-evidence-") as directory:
            stage = Path(directory)
            classes, empty = stage / "classes", stage / "empty"
            classes.mkdir()
            empty.mkdir()
            run_command(["javac", "--release", "17", "-proc:none", "-d", str(classes), str(PROBE), str(LOCAL_FLOW)],
                        output / "javac.log", 60, cwd=stage)
            for index, row in enumerate(rows.values(), 1):
                source = row["source"]
                if source["path"] not in cache:
                    snapshot = stage / Path(source["path"]).name
                    snapshot.write_text("\n".join(source["lines"]) + "\n", encoding="utf-8")
                    response = run_command(["java", "-cp", str(classes), "PathEvidenceProbe", str(snapshot),
                                            os.pathsep.join(map(str, jars)) or str(empty), str(empty)],
                                           output / f"java-{index:04d}.log", 60, cwd=stage)
                    cache[source["path"]] = decode_sites(response, len(source["lines"]))
                errors, sites, uses = cache[source["path"]]
                row["java_evidence"] = select_evidence(row["alert"], row["scanner_api"], sites, uses)
                row["java_evidence"]["unresolved_symbol_errors"] = errors
        with (output / "path_evidence.jsonl").open("x", encoding="utf-8") as stream:
            for row in rows.values():
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        metadata.update(state="COMPLETED", issue_count=len(rows))
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        metadata.update(state="FAILED", error=str(error))
        raise
    finally:
        save_json(output / "manifest.json", metadata)
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-run", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--java-classpath", type=Path, action="append", default=[])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.check:
        _, rows, _ = load_collection(args.from_run.resolve(), args.source_root.resolve())
        print(f"PATH_EVIDENCE_CHECK_OK: {len(rows)} warnings match source and line ranges")
    else:
        count = export_evidence(args.from_run, args.source_root, args.output, args.java_classpath)
        print(f"PATH_EVIDENCE_OK: {count} warnings. {args.output / 'path_evidence.jsonl'}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        raise SystemExit(str(error)) from None
