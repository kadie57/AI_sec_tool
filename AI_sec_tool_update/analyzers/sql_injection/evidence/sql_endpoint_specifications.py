"""Resolve the roles of APIs around one already collected SQL warning."""

from hashlib import sha256
import os
from pathlib import Path
import re
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from common.run_io import run_command


VERSION = "sql-endpoint-specifications-v2"
PROBE = Path(__file__).with_name("SqlEndpointProbe.java")
VALUE_PROBE = Path(__file__).with_name("SqlValueEvidence.java")
VALUE_VERSION = "jdbc-value-evidence-v10"
MAX_SOURCES = 8


def java_dependencies(jars):
    if shutil.which("java") is None:
        raise ValueError("Cần JDK 17 trở lên để xác minh chữ ký source/sink.")
    entries = []
    for value in jars:
        jar = value.expanduser().resolve()
        if jar.suffix != ".jar" or not jar.is_file() or os.pathsep in str(jar):
            raise ValueError(f"Classpath cần đường dẫn đến tệp JAR cục bộ: {jar}")
        with jar.open("rb") as stream:
            digest = sha256()
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
        entries.append({"path": str(jar), "sha256": digest.hexdigest()})
    return entries


def parse_probe(stdout, bundle, selected, value_evidence=False, *, source_candidates=False):
    files = bundle["files"]
    code = {key: file["masked_source"].splitlines() for key, file in files.items()}
    selected_lines = {node["line"] for node in selected.get("locations", [])}

    def ref(file_id, value):
        line = int(value)
        if not 1 <= line <= len(code[file_id]) or not code[file_id][line - 1].strip():
            raise ValueError("Tọa độ xác minh API nằm ngoài mã nguồn đã chuẩn bị.")
        return {"file_id": file_id, "line": line}

    result = {"version": VERSION, "scope": "one_sonar_alert", "sources": [], "sinks": []}
    if source_candidates:
        result["source_candidates"] = []
    query_by_position = {}
    values_by_position = {}
    dispatch_by_site = {}
    for text in stdout.splitlines():
        record, *fields = text.split("\t")
        if record == "STATUS":
            result["analysis"] = "partial_symbols" if int(fields[0]) else "resolved_symbols"
        elif record == "Q":
            file_id, position, column, owner, signature, argument = fields
            sink = {**ref(file_id, position), "column": int(column), "owner": owner, "signature": signature,
                    "role": "sql_text", "argument_index": 1, "argument": ref(file_id, argument), "bindings": []}
            query_by_position[position, column] = sink
            result["sinks"].append(sink)
        elif record == "B":
            position, column, binding, owner, signature, argument = fields
            query_by_position[position, column]["bindings"].append({
                **ref("F0", binding), "owner": owner, "signature": signature,
                "role": "bound_parameter_value", "argument_index": 2, "argument": ref("F0", argument),
                "association": "same_unreassigned_local_statement",
            })
        elif record == "T":
            position, column, index, argument = fields
            sink = query_by_position[position, column]
            file_id = sink["file_id"]
            sink["bindings"].append({
                **ref(file_id, position), "owner": sink["owner"], "signature": sink["signature"],
                "role": "bound_parameter_value", "argument_index": int(index), "argument": ref(file_id, argument),
                "association": "spring_jdbc_binding_argument",
            })
        elif record == "A" and value_evidence:
            position, column, file_id, call, call_column, owner, signature, index, argument, param = fields
            sink = query_by_position[position, column]
            site = sink.setdefault("resolved_caller", {
                **ref(file_id, call), "column": int(call_column), "owner": owner, "signature": signature,
                "scope": "single_resolved_direct_call_in_analyzed_sources", "arguments": [],
            })
            site["arguments"].append({"index": int(index), "argument": ref(file_id, argument),
                                      "parameter": ref("F0", param)})
        elif record == "V" and value_evidence:
            position, column, status, reason = fields
            sink = query_by_position[position, column]
            values_by_position[position, column] = {
                "call": {**ref(sink["file_id"], position), "column": int(column)},
                "sql_argument": sink["argument"], "status": status, "reason": reason, "evidence": [],
            }
        elif record == "E" and value_evidence:
            position, column, file_id, line, role = fields
            values_by_position[position, column]["evidence"].append({**ref(file_id, line), "role": role})
        elif record == "D" and value_evidence:
            position, column, file_id, line, name, scope, impl_file, impl_line, owner, returned = fields
            value = values_by_position[position, column]
            key = position, column, file_id, line, name
            if key not in dispatch_by_site:
                group = {**ref(file_id, line), "name": name, "argument_index": 1, "scope": scope,
                         "condition": "non_null_string_argument", "behavior": "returns_argument_unchanged", "targets": []}
                value.setdefault("dispatch_evidence", []).append(group)
                dispatch_by_site[key] = group
            dispatch_by_site[key]["targets"].append({**ref(impl_file, impl_line), "owner": owner,
                                                     "return": ref(impl_file, returned)})
        elif record == "F" and value_evidence:
            position, column, file_id, line, name, init_file, init_line, factory_file, factory_line, owner, signature = fields
            dispatch_by_site[position, column, file_id, line, name]["receiver_factory"] = {
                "initializer": ref(init_file, init_line), "declaration": ref(factory_file, factory_line),
                "owner": owner, "signature": signature, "packaged_resources": [], "direct_returns": [],
            }
        elif record == "R" and value_evidence:
            position, column, file_id, line, name, read_file, read_line, resource = fields
            factory = dispatch_by_site[position, column, file_id, line, name]["receiver_factory"]
            for key, item in files.items():
                if item["kind"] == "PROPERTIES" and item["path"] == f"src/main/resources/{resource}":
                    factory["packaged_resources"].append({"read": ref(read_file, read_line), "resource_file_id": key,
                                                          "scope": "packaged_snapshot"})
        elif record == "N" and value_evidence:
            position, column, file_id, line, name, return_file, return_line, owner = fields
            factory = dispatch_by_site[position, column, file_id, line, name]["receiver_factory"]
            factory["direct_returns"].append({**ref(return_file, return_line), "allocated_type": owner})
        elif record == "C" and source_candidates:
            file_id, position, column, owner, signature, fixed, *definition = fields
            candidate = {**ref(file_id, position), "column": int(column), "owner": owner, "signature": signature,
                         "fixed_dispatch": fixed == "true"}
            if definition:
                declaration, first, last = definition
                candidate["definition"] = {**ref(declaration, first), "end_line": ref(declaration, last)["line"]}
            if candidate not in result["source_candidates"]:
                result["source_candidates"].append(candidate)
        elif record == "I" and value_evidence:
            file_id, position, column, owner, signature = fields
            source = {**ref(file_id, position), "column": int(column), "owner": owner, "signature": signature,
                      "role": "servlet_request_read", "flow_to_sql": "not_established"}
            if source not in result["sources"]:
                result["sources"].append(source)
        elif record in {"S", "H"}:
            position, column, owner, signature, near_sink, *wrapper = fields
            location = ref("F0", position)
            if near_sink != "true" and location["line"] not in selected_lines:
                continue
            source = {**location, "column": int(column), "owner": owner, "signature": signature,
                      "role": "servlet_request_read", "flow_to_sql": "not_established"}
            if wrapper:
                helper_file, helper_line, read_owner, read_signature, dispatch = wrapper
                source.update(role="helper_returns_servlet_read" if dispatch != "declaration_only" else "helper_declaration_returns_servlet_read",
                              return_evidence={**ref(helper_file, helper_line), "owner": read_owner, "signature": read_signature},
                              dispatch=dispatch)
            result["sources"].append(source)
        else:
            raise ValueError("Đầu ra xác minh chữ ký Java không hợp lệ.")

    if "analysis" not in result:
        raise ValueError("Thiếu trạng thái phân giải chữ ký Java.")
    count = len(result["sinks"])
    result["sink_resolution"] = {0: "unresolved", 1: "one_verified_signature"}.get(count, "multiple_verified_signatures")
    sources = result["sources"]
    sources.sort(key=lambda source: (source["file_id"] != "F0" or source["line"] not in selected_lines,
                                     source["file_id"], source["line"], source["column"]))
    result["source_facts_omitted"] = max(0, len(sources) - MAX_SOURCES)
    result["sources"] = sources[:MAX_SOURCES]
    if value_evidence:
        if values_by_position.keys() != query_by_position.keys():
            raise ValueError("Thiếu trạng thái giá trị của đối số JDBC đã xác minh.")
        result["jdbc_value_evidence"] = {
            "version": VALUE_VERSION,
            "scope": "modeled_java_execution_up_to_the_reported_call",
            "status": "evaluated" if values_by_position else "jdbc_signature_unresolved",
            "arguments": list(values_by_position.values()),
        }
    return result


def dispatch_sites(bundle, selected):
    def location(ref):
        file_id, line = ref.get("file_id"), ref.get("line")
        return (file_id, line) if (isinstance(file_id, str) and file_id in bundle["files"] and re.fullmatch(r"F[0-9]+", file_id)
                                    and type(line) is int and line > 0) else None

    groups = {}
    for path in selected.get("anchored_paths", {}).get("paths", []):
        for edge in path["dispatch"]:
            call, name = location(edge), edge.get("name", "")
            if not call or not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                continue
            targets = {location(ref) for ref in edge["possible_targets"]}
            groups.setdefault((*call, name), set()).update(targets)
    return [(*call, *target) for call, targets in sorted(groups.items())[:8]
            if None not in targets and 2 <= len(targets) <= 4 for target in sorted(targets)]


def refresh_dispatch_evidence(row, dependencies, log):
    """Add conditional dispatch facts for existing unknown values after the project CPG stage."""
    selected, bundle = row["selected_evidence"], row["source_context"]
    arguments = selected.get("jdbc_value_evidence", {}).get("arguments", [])
    before = [item.pop("dispatch_evidence", []) for item in arguments]
    if not any(item["status"] == "unknown" for item in arguments) or not dispatch_sites(bundle, selected):
        return any(before)
    alert = SimpleNamespace(start=row["start_line"], end=row["end_line"])
    analyzed = infer_specifications(alert, bundle, selected, dependencies, log, value_evidence=True,
                                   experimental_dispatch_evidence=True)
    proven = {(item["call"]["line"], item["call"]["column"]): item
              for item in analyzed["jdbc_value_evidence"]["arguments"] if item.get("dispatch_evidence")}
    for argument in arguments:
        site = argument["call"]
        if (result := proven.get((site["line"], site["column"]))) and result["sql_argument"] == argument["sql_argument"]:
            argument["dispatch_evidence"] = result["dispatch_evidence"]
    return before != [item.get("dispatch_evidence", []) for item in arguments]


def infer_specifications(item, bundle, selected, dependencies, log, *, value_evidence=False, source_candidates=False,
                         experimental_dispatch_evidence=False):
    """Use only the verified source bundle and explicitly provided local classpath."""
    with TemporaryDirectory(prefix="sql-specifications-") as directory:
        staging = Path(directory)
        empty = staging / "empty"
        empty.mkdir()
        command = ["java", str(PROBE)]
        if value_evidence or source_candidates:
            run_command(["javac", "--release", "17", "-proc:none", "-d", str(staging), str(PROBE), str(VALUE_PROBE)],
                        log.with_name("java_value_probe_build.log"), 45, cwd=staging)
            command = ["java"]
            if caller_ids := bundle.get("snapshot_callers"):
                command.append("-Dsql.evidence.snapshotCallers=" + ",".join(caller_ids))
            if source_candidates:
                command.append("-Dsql.evidence.sourceCandidates=true")
            if experimental_dispatch_evidence and value_evidence and (sites := dispatch_sites(bundle, selected)):
                site_path = staging / "dispatch.tsv"
                site_path.write_text("".join("\t".join(map(str, row)) + "\n" for row in sites), encoding="utf-8")
                command.append(f"-Dsql.evidence.dispatchSites={site_path}")
            command.extend(["-cp", str(staging), "SqlValueEvidence"])
        command.extend([str(item.start), str(item.end),
                        os.pathsep.join(entry["path"] for entry in dependencies) or str(empty), str(empty)])
        for file_id, file in bundle["files"].items():
            if file["kind"] != "JAVA":
                continue
            path = staging / file_id / Path(file["path"]).name
            path.parent.mkdir()
            path.write_text(file["masked_source"], encoding="utf-8")
            command.extend([file_id, str(path)])
        stdout = run_command(command, log, 45, cwd=staging)
        return parse_probe(stdout, bundle, selected, value_evidence or source_candidates, source_candidates=source_candidates)
