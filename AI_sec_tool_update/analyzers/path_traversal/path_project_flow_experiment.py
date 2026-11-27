"""Add Joern flow candidates to a frozen CWE-22 evidence export."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from common.joern_project import run_joern_script, stage_classpath, stage_snapshot
from common.run_io import save_json
from common.source_text import mask_java

from .evidence import path_cpg
from .prepare_path_evidence import LOCAL_FLOW, PROBE, VERSION, load_collection


PROJECT_VERSION = "path-evidence-project-v1"
VALUE_PROJECT_VERSION = "path-evidence-project-value-v1"
PROJECT_VERSIONS = {PROJECT_VERSION, VALUE_PROJECT_VERSION}
JAVA_ROOT = "src/main/java/"


def stage_helpers(repo, commit, files, project):
    if not re.fullmatch(r"[a-f0-9]{40}", commit or ""):
        raise ValueError("The collection must specify a full BenchmarkJava commit.")

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, timeout=60).stdout

    def source_at_commit(name):
        return git("show", f"{commit}:{name}")

    sample_paths = set()
    for name, info in files.items():
        if JAVA_ROOT not in name:
            raise ValueError(f"Cannot locate source in the pinned BenchmarkJava tree: {name}")
        relative = JAVA_ROOT + name.split(JAVA_ROOT, 1)[1]
        if sha256(source_at_commit(relative)).hexdigest() != info["sha256"]:
            raise ValueError(f"Collection source differs from the pinned BenchmarkJava commit: {name}")
        sample_paths.add(relative)

    paths = git("ls-tree", "-rz", "--name-only", commit, "--", JAVA_ROOT).decode("utf-8").split("\0")
    helpers = {}
    for name in paths:
        relative = Path(name)
        if (not name.startswith(JAVA_ROOT) or relative.suffix != ".java" or name in sample_paths
                or "testcode" in relative.parts):
            continue
        if relative.as_posix() != name or ".." in relative.parts or any(c in name for c in "\t\r\n"):
            raise ValueError(f"Invalid helper path in the pinned repository: {name}")
        raw = source_at_commit(name)
        staged = project / relative
        source = mask_java(raw.decode("utf-8"))
        staged.parent.mkdir(parents=True, exist_ok=True)
        with staged.open("x", encoding="utf-8") as stream:
            stream.write(source)
        helpers[name] = {"path": name, "kind": "JAVA", "sha256": sha256(raw).hexdigest(), "masked_source": source}
    return helpers


def load_baseline(evidence, collection, source_root):
    scan, verified, hashes = load_collection(collection, source_root)
    baseline = json.loads((evidence.parent / "manifest.json").read_bytes())
    if (baseline["state"] != "COMPLETED" or baseline["version"] != VERSION
            or baseline["collection_hashes"] != hashes or baseline["analysis_id"] != scan["analysis_id"]):
        raise ValueError("Use completed same-method evidence from this exact SonarQube collection.")
    raw = evidence.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    seen = set()
    for row in rows:
        issue = row["alert"]["issue_id"]
        if issue in seen or issue not in verified or any(row[key] != value for key, value in verified[issue].items()):
            raise ValueError(f"Base evidence differs from the verified source or warning: {issue}")
        seen.add(issue)
    if seen != verified.keys() or len(rows) != baseline["issue_count"]:
        raise ValueError("Base evidence does not cover the original CWE-22 warning set.")
    return scan, baseline, rows, sha256(raw).hexdigest()


def export_project_flows(evidence, collection, source_root, output, image, benchmark_root=None, classpath=(),
                         *, value_facts=False):
    evidence, collection, source_root, output = (p.resolve() for p in (evidence, collection, source_root, output))
    protected = [collection, source_root, evidence.parent]
    if benchmark_root is not None:
        benchmark_root = benchmark_root.resolve()
        protected.append(benchmark_root)
    if any(output.is_relative_to(path) for path in protected):
        raise ValueError("Write project evidence outside the input directories.")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("Use a pinned local Joern image ID of the form sha256:<64 digits>.")
    scan, baseline, rows, base_hash = load_baseline(evidence, collection, source_root)
    commit = scan.get("benchmark_commit")
    if commit and benchmark_root is None:
        raise ValueError("Pass --benchmark-root to include helpers from the collection's BenchmarkJava commit.")
    output.mkdir(parents=True, exist_ok=False)
    graph, project = output / "graph", output / "project"
    graph.mkdir()
    metadata = {
        "version": VALUE_PROJECT_VERSION if value_facts else PROJECT_VERSION,
        "state": "IN_PROGRESS", "analysis_id": scan["analysis_id"],
        "project": scan["project"], "collection_hashes": baseline["collection_hashes"],
        "baseline_evidence_sha256": base_hash, "benchmark_commit": commit, "joern_image_id": image,
        "classpath": baseline["classpath"],
        "tool_hashes": {file.name: sha256(file.read_bytes()).hexdigest() for file in (
            Path(__file__), Path(path_cpg.__file__), Path(path_cpg.__file__).with_name("path_slice.sc"),
            PROBE, LOCAL_FLOW,
        )},
        "scope": "Collected Java files plus pinned benchmark support sources when supplied. Static HTTP-to-file-operand candidates.",
    }
    save_json(output / "manifest.json", metadata)
    try:
        files = stage_snapshot(source_root, scan["source_hashes"], project)
        helpers = stage_helpers(benchmark_root, commit, files, project) if benchmark_root else {}
        files.update(helpers)
        metadata["helper_hashes"] = {name: item["sha256"] for name, item in helpers.items()}
        jars = stage_classpath(baseline["classpath"], classpath, graph)
        errors, indexed = path_cpg.project_sites(files, project, graph, jars, value_facts=value_facts)
        sources = [key for key, sites in indexed.items() if len(sites) == 1 and sites[0]["role"] == "external_input_api"]
        operands = [path_cpg.locate_operands(row, indexed, value_facts=value_facts) for row in rows]
        targets = list(dict.fromkeys(item[0] for linked in operands for item in linked))
        path_cpg.write_query(graph, jars, sources, targets)
        stdout = run_joern_script(project, graph, image, container_workdir="/tmp")
        traces, matched = path_cpg.parse_query(stdout, sources, targets)
        code = {name: file["masked_source"].splitlines() for name, file in files.items()}
        hashes = {name: file["sha256"] for name, file in files.items()}
        audit = []
        with (output / "path_evidence.jsonl").open("x", encoding="utf-8") as stream:
            for row, linked in zip(rows, operands, strict=True):
                row["project_flow"] = path_cpg.bundle(row, linked, traces, indexed, code, hashes, audit=audit)
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        if value_facts:
            save_json(graph / "pruned-candidates.json", audit)
            metadata["pruned_cpg_paths"] = len(audit)
        metadata.update(state="COMPLETED", issue_count=len(rows), java_file_count=len(files),
                        java_symbol_errors=errors, typed_http_sites=len(sources), matched_cpg_http_sites=matched,
                        verified_file_operands=len(targets), cpg_artifact="graph/snapshot.bin")
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        metadata.update(state="FAILED", error=str(error))
        raise
    finally:
        save_json(output / "manifest.json", metadata)
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--collection", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--benchmark-root", type=Path)
    parser.add_argument("--java-classpath", type=Path, action="append", default=[])
    parser.add_argument("--joern-image-id", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--value-facts", action="store_true",
                        help="Link bounded Java value evidence and exclude demonstrably conflicting CPG candidates.")
    args = parser.parse_args()
    count = export_project_flows(args.evidence, args.collection, args.source_root, args.out,
                                 args.joern_image_id, args.benchmark_root, args.java_classpath,
                                 value_facts=args.value_facts)
    print(f"PATH_PROJECT_FLOWS_OK: {count} warnings. {args.out / 'path_evidence.jsonl'}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
