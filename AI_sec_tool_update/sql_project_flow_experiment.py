"""Recompute SQL warning paths on a shared, verified Java snapshot CPG."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from time import monotonic

from sql_llm_experiment import digest, read, write
from sql_source_spec_experiment import load_proposals, proposed_sources, read_evidence
from sql_pipeline.evidence.sql_project_paths import (
    SCOPE, VERSION, case_files, query_snapshot, read_servlet_sites, stage_classpath, stage_snapshot, trace_files,
)
from sql_pipeline.evidence.sql_source_paths import endpoints, select_paths
from sql_pipeline.evidence.sql_endpoint_specifications import refresh_dispatch_evidence


WARNING_IDENTITY = ("issue_id", "component", "rule", "start_line", "end_line", "source_sha256")


def sites_for_alert(frozen, servlet_sites, file_ids):
    origins = {(site["file_id"], site["line"], site["name"]): site for site in frozen}
    for site in servlet_sites:
        file_id = file_ids[site["path"]]
        key = (file_id, site["line"], site["name"])
        origins.setdefault(key, {**site, "file_id": file_id})
    return list(origins.values())


def update_evidence(row, files, trace):
    selected = row["selected_evidence"]
    previous = selected.get("anchored_paths", {})
    new_paths, old_paths = trace["paths"], previous.get("paths", [])
    # Preserve the exact triage payload when the displayed path evidence is equal.
    if new_paths == old_paths and (not new_paths or all(trace[key] == previous.get(key) for key in (
            "search_limit_hit", "paths_not_shown"))):
        return False
    visible = set()
    for path in new_paths:
        visible.update(ref["file_id"] for ref in (path["source"], *path["steps"], path["sink"]))
        for edge in path["dispatch"]:
            visible.add(edge["file_id"])
            visible.update(ref["file_id"] for ref in edge["possible_targets"])
    original = row["source_context"]["files"]
    original.update({key: {**files[key], "path_context_only": True} for key in files if key in visible and key not in original})
    selected["anchored_paths"] = trace
    return True


def run_project(base, collection, source_root, output, *, comparison=None, inventory=None, labels=None, jars=(),
                experimental_dispatch_evidence=False):
    base, output = base.resolve(), output.resolve()
    base_sha, base_rows = read_evidence(base)
    base_manifest = read(base.with_name("manifest.json"))
    collection_raw = (collection / "manifest.json").read_bytes()
    if (base_manifest["state"] != "COMPLETED"
            or sha256(collection_raw).hexdigest() != base_manifest["collection_manifest_sha256"]):
        raise ValueError("Collection does not match the completed baseline")
    if output.is_relative_to(source_root.resolve()) or output.is_relative_to(collection.resolve()):
        raise ValueError("Put evidence output outside the collection and source snapshot")
    image = base_manifest["joern_image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("Need an immutable Joern image id")
    if (inventory is None) != (labels is None):
        raise ValueError("Pass the source inventory and label directory together")
    inputs, predictions = (load_proposals(inventory, labels) if inventory else ({}, {}))
    if inputs and (inputs["evidence_sha256"] != base_sha or inputs["joern_image_id"] != image):
        raise ValueError("Source proposals differ from the baseline")
    comparison_rows = base_rows
    if comparison:
        comparison = comparison.resolve()
        captured = read(comparison.with_name("manifest.json"))
        if (not inputs or captured["state"] != "COMPLETED" or captured["baseline_evidence_sha256"] != base_sha
                or captured["source_inventory_sha256"] != digest(inputs) or captured["joern_image_id"] != image):
            raise ValueError("Comparison does not match the frozen source proposals")
        _, comparison_rows = read_evidence(comparison)
    if len(comparison_rows) != len(base_rows) or not base_rows:
        raise ValueError("Comparison and baseline must contain the same warnings")

    output.mkdir(parents=True, exist_ok=False)
    graph = output / "graph"
    graph.mkdir()
    project = graph / "java"
    snapshot = stage_snapshot(source_root, json.loads(collection_raw)["source_hashes"], project)
    dependencies = stage_classpath(base_manifest["endpoint_specifications"]["java_classpath"], jars, graph)
    servlet_sites, jdk_errors = read_servlet_sites(snapshot, project, dependencies, graph)
    servlet_files = {site["path"] for site in servlet_sites}
    tasks, cases = [], []
    for index, (original, row) in enumerate(zip(base_rows, comparison_rows), 1):
        if any(original[key] != row[key] for key in WARNING_IDENTITY):
            raise ValueError("Comparison warning differs in identity or source coordinates")
        for field in ("source_path", "cpg_artifact"):
            path = (base.parent / original[field]).resolve()
            if not path.is_relative_to(base.parent) or not path.is_file():
                raise ValueError(f"Baseline artifact is unavailable: {field}")
            row[field] = os.path.relpath(path, output)
        specs = original["selected_evidence"]["endpoint_specifications"].copy()
        frozen, sink = endpoints(specs)
        cases.append({"issue_id": row["issue_id"], "status": "jdbc_signature_not_unique", "changed_evidence": False})
        if not sink:
            continue
        files, file_ids = case_files(row["source_context"]["files"], snapshot, servlet_files)
        values = original["selected_evidence"].get("jdbc_value_evidence", {}).get("arguments", [])
        modeled_constant = len(values) == 1 and values[0]["status"] == "constant_sql_text"
        if inputs and not modeled_constant:
            specs["source_proposals"] = list(proposed_sources(original, frozen, inputs, predictions).values())
            frozen, _ = endpoints(specs)
        sources = sites_for_alert(frozen, servlet_sites, file_ids)
        tasks.append((index, files, sources, sink))

    print(f"Building one CPG for {len(snapshot)} Java files and querying {len(tasks)} alerts", flush=True)
    started = monotonic()
    traces = query_snapshot(project, graph, dependencies, image, tasks)
    elapsed = round(monotonic() - started, 3)
    classpath = [{"path": str(path)} for path in dependencies]
    for index, files, sources, sink in tasks:
        output_rows = traces[index]
        files, _ = case_files(files, snapshot, trace_files(output_rows, snapshot))
        trace = select_paths(output_rows, files, sources, sink)
        trace.update(version=VERSION, scope=SCOPE,
                     interpretation="Candidate dataflow. Runtime branch and dispatch feasibility require separate evidence.")
        write(output / f"issue-{index:04d}.json", trace)
        row = comparison_rows[index - 1]
        changed = update_evidence(row, files, trace)
        dispatch_changed = experimental_dispatch_evidence and refresh_dispatch_evidence(
            row, classpath, output / f"dispatch-{index:04d}.log")
        cases[index - 1].update(status=trace["status"], candidate_paths_found=trace["candidate_paths_found"],
                                matched_sources=trace["matched_sources"], displayed_paths=len(trace["paths"]),
                                changed_evidence=changed or dispatch_changed)

    with (output / "sql_evidence.jsonl").open("x", encoding="utf-8") as stream:
        for row in comparison_rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    write(output / "project_paths.json", {"cases": cases})
    write(graph / "inputs.json", {"sources": {key: item["sha256"] for key, item in snapshot.items()},
                                 "classpath": base_manifest["endpoint_specifications"]["java_classpath"],
                                 "servlet_sites": servlet_sites, "jdk_symbol_errors": jdk_errors})
    write(output / "manifest.json", {"version": VERSION, "state": "COMPLETED", "baseline_evidence": str(base),
                                     "baseline_evidence_sha256": base_sha, "joern_image_id": image,
                                     "collection_manifest_sha256": sha256(collection_raw).hexdigest(),
                                     "comparison_evidence": str(comparison or base), "cpg_artifact": "graph/snapshot.bin",
                                     "java_file_count": len(snapshot), "jdk_symbol_errors": jdk_errors,
                                     "build_and_query_elapsed_seconds": elapsed,
                                     "result_count": len(cases)})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path, help="Evidence before model-generated sources are applied")
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, help="Evidence produced with the original per-alert CPGs")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--java-classpath", type=Path, action="append", default=[])
    parser.add_argument("--experimental-dispatch-evidence", action="store_true",
                        help="Thử phân tích đích gọi interface từ đường đi trong CPG.")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    cases = run_project(args.base, args.collection, args.source_root, args.out, comparison=args.comparison,
                        inventory=args.inventory, labels=args.labels, jars=args.java_classpath,
                        experimental_dispatch_evidence=args.experimental_dispatch_evidence)
    print(f"Completed {len(cases)} alerts. {sum(bool(case.get('displayed_paths')) for case in cases)} have project paths.")


if __name__ == "__main__":
    main()
