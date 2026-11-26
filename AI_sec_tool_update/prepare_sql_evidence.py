"""Prepare static evidence for saved SonarQube SQL/JDBC findings."""

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from sql_pipeline.cwe_mapper import MAPPING_VERSION, get_cwe_info
from sql_pipeline.evidence.joern_sql import issue_range, resolve_issue_path, run_joern_slicing
from sql_pipeline.evidence.source_text import mask_java
from sql_pipeline.evidence.sql_context_bundle_v1 import Repository, build as build_sql_context
from sql_pipeline.evidence.sql_endpoint_specifications import VERSION as SPECIFICATION_VERSION
from sql_pipeline.evidence.sql_endpoint_specifications import VALUE_VERSION
from sql_pipeline.evidence.sql_endpoint_specifications import infer_specifications, java_dependencies, refresh_dispatch_evidence
from sql_pipeline.evidence.sql_evidence_selection import select_evidence
from sql_pipeline.evidence.sql_snapshot_callers import VERSION as SNAPSHOT_CALLERS_VERSION
from sql_pipeline.evidence.sql_snapshot_callers import add_snapshot_callers
from sql_pipeline.evidence.sql_source_paths import VERSION as SOURCE_PATHS_VERSION
from sql_pipeline.evidence.sql_source_paths import infer_source_paths
from sql_pipeline.run_io import redact, run_command, save_json


@dataclass(frozen=True)
class EvidenceInput:
    issue: dict
    relative: Path
    source: bytes
    source_hash: str
    start: int
    end: int


def prepare_inputs(collection, source_root, selected_components):
    manifest_raw = (collection / "manifest.json").read_bytes()
    issues_raw = (collection / "issues.json").read_bytes()
    manifest = json.loads(manifest_raw)
    payload = json.loads(issues_raw)
    issues = payload.get("issues") if isinstance(payload, dict) else payload
    if not isinstance(manifest, dict) or not isinstance(issues, list):
        raise ValueError("Manifest hoặc danh sách cảnh báo không hợp lệ.")
    if manifest.get("state") not in {"COLLECTED", "COMPLETED"} or not manifest.get("analysis_id"):
        raise ValueError("Cần lượt thu thập đã hoàn tất và có analysis_id.")
    project = manifest.get("project")
    source_hashes = manifest.get("source_hashes")
    if not isinstance(project, str) or not project or not isinstance(source_hashes, dict):
        raise ValueError("Manifest thiếu tên project hoặc bảng hash mã nguồn.")

    seen = set()
    matched = set()
    inputs = []
    for issue in issues:
        if not isinstance(issue, dict) or not isinstance(issue.get("key"), str) or not issue["key"]:
            raise ValueError("Cảnh báo thiếu mã nhận dạng.")
        if issue["key"] in seen:
            raise ValueError(f"Cảnh báo trùng mã nhận dạng: {issue['key']}")
        seen.add(issue["key"])
        rule = issue.get("rule")
        if not isinstance(rule, str):
            raise ValueError(f"Cảnh báo {issue['key']} thiếu rule.")
        mapping = get_cwe_info(rule)
        if not mapping["supported"] or mapping["cwe_id"] != "CWE-89":
            continue
        component = issue.get("component")
        if not isinstance(component, str):
            raise ValueError(f"Cảnh báo {issue['key']} thiếu component.")
        if selected_components and component not in selected_components:
            continue
        matched.add(component)
        path = resolve_issue_path(issue, project, source_root)
        relative = path.relative_to(source_root)
        raw = path.read_bytes()
        digest = sha256(raw).hexdigest()
        if source_hashes.get(relative.as_posix()) != digest:
            raise ValueError(f"Mã nguồn khác hash của lượt quét: {relative}")
        start, end = issue_range(issue)
        if end > len(raw.decode("utf-8").splitlines()):
            raise ValueError(f"Vùng cảnh báo vượt số dòng mã nguồn: {relative}")
        inputs.append(EvidenceInput(issue, relative, raw, digest, start, end))

    missing = selected_components - matched
    if missing:
        raise ValueError("Component không có cảnh báo SQL được hỗ trợ: " + ", ".join(sorted(missing)))
    if not inputs:
        raise ValueError("Lượt thu thập không có cảnh báo SQL được hỗ trợ.")
    provenance = {
        "collection": str(collection),
        "collection_manifest_sha256": sha256(manifest_raw).hexdigest(),
        "collection_issues_sha256": sha256(issues_raw).hexdigest(),
        "analysis_id": manifest["analysis_id"],
        "project": project,
        "mapping_version": MAPPING_VERSION,
        "benchmark_commit": manifest.get("benchmark_commit"),
    }
    return inputs, provenance


def read_recorded_joern(directory, inputs):
    index = json.loads((directory / "index.json").read_bytes())
    if not isinstance(index, dict) or not isinstance(index.get("artifacts"), dict):
        raise ValueError("Chỉ mục Joern đã lưu không hợp lệ.")
    artifacts = index["artifacts"]
    flows = {}
    for item in inputs:
        issue_id = item.issue["key"]
        entry = artifacts.get(issue_id)
        expected = {
            "component": item.issue["component"], "start_line": item.start,
            "end_line": item.end, "source_sha256": item.source_hash,
        }
        if not isinstance(entry, dict) or any(entry.get(key) != value for key, value in expected.items()):
            raise ValueError(f"Bản ghi Joern khác cảnh báo, dòng hoặc hash nguồn: {issue_id}")
        filename = entry.get("file")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ValueError(f"Tên artifact Joern không hợp lệ: {issue_id}")
        path = directory / filename
        if path.is_symlink():
            raise ValueError(f"Artifact Joern không được là liên kết: {filename}")
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != entry.get("sha256"):
            raise ValueError(f"SHA-256 của artifact Joern không khớp: {filename}")
        flow = json.loads(raw)
        keys = ("flow_count", "sink_call_count", "sink_argument_count")
        if not isinstance(flow, dict) or any(type(flow.get(k)) is not int or flow[k] < 0 for k in keys):
            raise ValueError(f"Số luồng hoặc số lời gọi Joern không hợp lệ: {filename}")
        if not isinstance(flow.get("paths"), str) or bool(flow["paths"].strip()) != bool(flow["flow_count"]):
            raise ValueError(f"Bảng đường đi Joern không khớp số luồng: {filename}")
        flows[issue_id] = (raw, flow)
    return index.get("joern_image_id"), flows


def prepare_source_context(inputs, commit, benchmark_root):
    repository = None
    unavailable = "Lượt quét không có commit BenchmarkJava để ghép helper."
    if commit:
        try:
            repository = Repository(benchmark_root, commit)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            unavailable = "Không đọc được commit đã quét từ repo BenchmarkJava cục bộ."

    bundles = {}
    for item in inputs:
        relative = item.relative.as_posix()
        main_file = {
            "file_id": "F0", "path": relative, "kind": "JAVA",
            "sha256": item.source_hash, "masked_source": mask_java(item.source.decode("utf-8")),
        }
        bundle = {"commit": None, "files": {"F0": main_file}, "links": [], "missing_context": []}
        _, marker, suffix = ("/" + relative).partition("/src/main/java/")
        if repository is None:
            bundle["missing_context"].append(unavailable)
        elif not marker:
            bundle["missing_context"].append("Không xác định được đường dẫn Git của file chính.")
        else:
            try:
                candidate = build_sql_context(repository, "src/main/java/" + suffix, item.source)
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                bundle["missing_context"].append(redact(str(exc)))
            else:
                candidate["files"] = {
                    ident: {key: value for key, value in record.items() if key != "source"}
                    for ident, record in candidate["files"].items()
                }
                bundle = candidate
        bundles[item.issue["key"]] = bundle
    return bundles


def export_evidence(inputs, provenance, output, bundles, recorded, specification_dependencies=None, *,
                    jdbc_values=False, joern_source_paths=False, snapshot_callers=False,
                    experimental_dispatch_evidence=False):
    if experimental_dispatch_evidence and (not jdbc_values or not joern_source_paths or specification_dependencies is None):
        raise ValueError("Bằng chứng interface thử nghiệm cần phân tích giá trị JDBC và đường nguồn Joern.")
    if joern_source_paths and recorded is not None:
        image_id = recorded[0]
        if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("Phân tích liên tệp cần ID SHA-256 của image Joern trong chỉ mục đã lưu.")
    output.mkdir(parents=True, exist_ok=False)
    manifest = {
        **provenance,
        "state": "IN_PROGRESS",
        "issue_count": len(inputs),
        "joern_mode": "recorded" if recorded is not None else "live",
        "limitations": [
            "Truy vấn Joern nền phân tích phạm vi một tệp Java.",
            "Luồng từ tham số là một ứng viên, chưa xác nhận nguồn bên ngoài.",
            "Không tìm thấy luồng trong truy vấn hiện tại chưa xác nhận mã an toàn.",
        ],
    }
    if specification_dependencies is not None:
        manifest["endpoint_specifications"] = {"version": SPECIFICATION_VERSION, "java_classpath": specification_dependencies}
    if jdbc_values:
        manifest["jdbc_value_evidence"] = {"version": VALUE_VERSION}
    if experimental_dispatch_evidence:
        manifest["experimental_dispatch_evidence"] = True
    if snapshot_callers:
        manifest["snapshot_callers"] = {"version": SNAPSHOT_CALLERS_VERSION}
    if joern_source_paths:
        manifest["joern_source_paths"] = {"version": SOURCE_PATHS_VERSION, "mode": "live"}
        manifest["limitations"].append("Đường liên tệp là ứng viên. Cần bằng chứng riêng cho nhánh và đích gọi lúc chạy.")
    manifest_path = output / "manifest.json"
    save_json(manifest_path, manifest)
    snapshot = output / "sources"
    saved_sources = set()
    records = []
    dataset = []
    try:
        if recorded is None:
            image = os.getenv("JOERN_IMAGE", "ghcr.io/joernio/joern:nightly")
            details = json.loads(run_command(["docker", "image", "inspect", image], output / "joern_image.log", 30))
            image_id = details[0]["Id"]
        else:
            image_id, flows = recorded
        manifest["joern_image_id"] = image_id
        for index, item in enumerate(inputs, 1):
            source_file = snapshot / item.relative
            if item.relative not in saved_sources:
                source_file.parent.mkdir(parents=True, exist_ok=True)
                source_file.write_bytes(item.source)
                saved_sources.add(item.relative)
            artifact = output / f"issue-{index:04d}"
            artifact.mkdir()
            issue_id = item.issue["key"]
            if recorded is None:
                flow = run_joern_slicing(source_file, item.issue, snapshot, artifact, image_id)
            else:
                raw, flow = flows[issue_id]
                (artifact / "cpg_evidence.json").write_bytes(raw)
            record = {
                "issue_id": issue_id,
                "rule": item.issue["rule"],
                "cwe_id": "CWE-89",
                "component": item.issue["component"],
                "start_line": item.start,
                "end_line": item.end,
                "source_path": source_file.relative_to(output).as_posix(),
                "source_sha256": item.source_hash,
                "cpg_artifact": (artifact / "cpg_evidence.json").relative_to(output).as_posix(),
                "flow_count": flow["flow_count"],
                "sink_call_count": flow["sink_call_count"],
                "sink_argument_count": flow["sink_argument_count"],
            }
            bundle = bundles[issue_id]
            selected_evidence = select_evidence(item, bundle, flow)
            if specification_dependencies is not None:
                specifications = infer_specifications(item, bundle, selected_evidence, specification_dependencies,
                                                     artifact / "java_specifications.log", value_evidence=jdbc_values)
                if jdbc_values:
                    selected_evidence["jdbc_value_evidence"] = specifications.pop("jdbc_value_evidence")
                selected_evidence["endpoint_specifications"] = specifications
                if joern_source_paths:
                    anchored = artifact / "anchored"
                    anchored.mkdir()
                    selected_evidence["anchored_paths"] = infer_source_paths(bundle, specifications, anchored, image_id)
            records.append(record)
            row = {**record, "source_context": bundle, "joern": flow, "selected_evidence": selected_evidence}
            if experimental_dispatch_evidence:
                refresh_dispatch_evidence(row, specification_dependencies, artifact / "java_dispatch.log")
            dataset.append(row)
        manifest["state"] = "COMPLETED"
    except (OSError, ValueError, RuntimeError, KeyError, IndexError) as exc:
        manifest.update(state="FAILED", error=redact(str(exc)))
        raise
    finally:
        save_json(output / "evidence.json", records)
        with (output / "sql_evidence.jsonl").open("x", encoding="utf-8") as stream:
            for row in dataset:
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        manifest["result_count"] = len(records)
        save_json(manifest_path, manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-run", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--only-component", action="append", default=[])
    parser.add_argument("--recorded-joern", type=Path, help="Đọc và kiểm tra hash của CPG nền đã lưu.")
    parser.add_argument("--joern-source-paths", action="store_true",
                        help="Chạy Joern trên gói Java để nối các API đọc HTTP đã xác minh tới JDBC.")
    parser.add_argument("--infer-specifications", action="store_true", help="Xác minh source/sink của từng cảnh báo bằng JDK.")
    parser.add_argument("--infer-jdbc-values", action="store_true", help="Bổ sung bằng chứng nhánh và giá trị tới đối số SQL.")
    parser.add_argument("--experimental-dispatch-evidence", action="store_true",
                        help="Thử phân tích đích gọi interface. Cần --infer-jdbc-values và --joern-source-paths.")
    parser.add_argument("--snapshot-callers", action="store_true",
                        help="Đối chiếu đối số ở tệp gọi trong snapshot Java của lượt thu thập.")
    parser.add_argument("--java-classpath", type=Path, action="append", default=[], metavar="JAR",
                        help="JAR thư viện hoặc kiểu Java đã biên dịch của snapshot. Có thể lặp lại.")
    default_benchmark = Path.home() / "AI_sec_benchmarks" / "BenchmarkJava"
    parser.add_argument("--benchmark-root", type=Path,
                        default=Path(os.getenv("OWASP_BENCHMARK_ROOT", str(default_benchmark))))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Kiểm tra manifest, cảnh báo và hash Java.")
    mode.add_argument("--output", type=Path, help="Thư mục đầu ra mới cho bằng chứng Joern.")
    args = parser.parse_args()
    if args.java_classpath and not args.infer_specifications:
        parser.error("--java-classpath cần --infer-specifications")
    if args.infer_jdbc_values and not args.infer_specifications:
        parser.error("--infer-jdbc-values cần --infer-specifications")
    if args.snapshot_callers and not args.infer_jdbc_values:
        parser.error("--snapshot-callers cần --infer-jdbc-values")
    if args.joern_source_paths and not args.infer_specifications:
        parser.error("--joern-source-paths cần --infer-specifications")
    if args.experimental_dispatch_evidence and not (args.infer_jdbc_values and args.joern_source_paths):
        parser.error("--experimental-dispatch-evidence cần --infer-jdbc-values và --joern-source-paths")
    collection = args.from_run.resolve()
    try:
        source_root = args.source_root.resolve()
        inputs, provenance = prepare_inputs(collection, source_root, set(args.only_component))
        bundles = prepare_source_context(inputs, provenance["benchmark_commit"], args.benchmark_root.expanduser())
        if args.snapshot_callers:
            manifest_raw = (collection / "manifest.json").read_bytes()
            if sha256(manifest_raw).hexdigest() != provenance["collection_manifest_sha256"]:
                raise ValueError("Manifest đã thay đổi trong lúc chuẩn bị bằng chứng.")
            add_snapshot_callers(inputs, bundles, source_root, json.loads(manifest_raw)["source_hashes"])
        recorded = read_recorded_joern(args.recorded_joern.resolve(), inputs) if args.recorded_joern else None
        dependencies = java_dependencies(args.java_classpath) if args.infer_specifications else None
        if args.check:
            print(f"SQL_EVIDENCE_CHECK_OK: {len(inputs)} cảnh báo khớp nguồn và vùng dòng.")
            return 0
        output = args.output.resolve()
        if output.is_relative_to(collection):
            raise ValueError("Đặt đầu ra bên ngoài thư mục lượt thu thập.")
        export_evidence(inputs, provenance, output, bundles, recorded, dependencies,
                        jdbc_values=args.infer_jdbc_values, joern_source_paths=args.joern_source_paths,
                        snapshot_callers=args.snapshot_callers,
                        experimental_dispatch_evidence=args.experimental_dispatch_evidence)
        print(f"SQL_EVIDENCE_OK: {len(inputs)} cảnh báo. Kết quả: {output / 'sql_evidence.jsonl'}")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, IndexError) as exc:
        print(f"[LỖI] {redact(str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
