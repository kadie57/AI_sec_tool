"""Route saved SonarQube issues to the existing SQL/Path/Command analyzers.

Run from ~/AI_sec_tool. --check is offline. This adapter does not rescan Sonar,
train a model, close issues, or change the existing analyzer files/prompts.
Resume skips completed issue checkpoints (including error results). An interrupted
issue requires --retry-incomplete and may repeat up to 4 generation calls.
"""
import argparse
import copy
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone

VERSION = "multi-sql89-path22-command78-v6-sql-source-http"
RULES = {
    "findsecbugs:SQL_INJECTION_JDBC": ("sql", "CWE-89"),
    "findbugs:SQL_INJECTION_JDBC": ("sql", "CWE-89"),
    "java:S3649": ("sql", "CWE-89"),
    "findsecbugs:PATH_TRAVERSAL_IN": ("path", "CWE-22"),
    "findsecbugs:COMMAND_INJECTION": ("command", "CWE-78"),
}
SQL_FILES = ("master_pipeline_combined_v1.py", "master_pipeline_source_v1.py",
             "master_pipeline_v6.py", "master_pipeline.py", "triage_v5.py",
             "triage_v6.py", "validate_v6.py", "source_audit_v2.py",
             "replay_source_merge.py", "check_sql_prompt_controls.py",
             "cwe_mapper.py", "iris_prompter.py", "sql_source_audit_v4.py",
             "run_holdout_system.py")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(value):
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False).encode())


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
            tmp = Path(f.name)
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp and tmp.exists():
            tmp.unlink()


def stamp():
    return datetime.now(timezone.utc).isoformat()


def prepare(root, collection):
    manifest = read(collection / "manifest.json")
    bundle = read(collection / "issues.json")
    if manifest.get("state") not in ("COLLECTED", "COMPLETED") or not manifest.get("analysis_id"):
        raise ValueError("Cần lượt quét COLLECTED/COMPLETED có analysis_id.")
    project = manifest.get("project")
    if not isinstance(project, str) or not project:
        raise ValueError("Thiếu project trong manifest.")
    issues = bundle.get("issues") if isinstance(bundle, dict) else bundle
    if not isinstance(issues, list) or any(not isinstance(i, dict) for i in issues):
        raise ValueError("issues.json không phải danh sách cảnh báo hợp lệ.")
    keys = [i.get("key") for i in issues]
    if any(not isinstance(k, str) or not k for k in keys) or len(set(keys)) != len(keys):
        raise ValueError("Cảnh báo thiếu key hoặc trùng key.")
    items = []
    for index, issue in enumerate(issues, 1):
        route = RULES.get(issue.get("rule"))
        raw, rel = None, None
        if route:
            component = issue.get("component", "")
            if not component.startswith(project + ":"):
                raise ValueError("Component không thuộc project.")
            rel = component[len(project) + 1:]
            relative = Path(rel)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("Đường dẫn nguồn không hợp lệ.")
            source_path = (root / relative).resolve()
            if not source_path.is_relative_to(root) or source_path.suffix != ".java":
                raise ValueError("Nguồn phải là Java trong project.")
            raw = source_path.read_bytes()
            if manifest.get("source_hashes", {}).get(rel) != sha(raw):
                raise ValueError(f"{rel}: nguồn khác lần quét hoặc thiếu hash; cần quét lại.")
            source = raw.decode("utf-8")
            span = issue.get("textRange") or {}
            start, end = span.get("startLine", issue.get("line")), span.get("endLine", span.get("startLine", issue.get("line")))
            if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(source.splitlines()):
                raise ValueError(f"{rel}: vùng dòng cảnh báo không hợp lệ.")
            if route[0] == "sql" and "\r" in source:
                raise ValueError(f"{rel}: SQL adapter cũ chuẩn hóa xuống dòng. Chuyển file sang LF rồi quét lại để hash nhất quán.")
        items.append({"index": index, "issue": issue, "route": route[0] if route else None,
                      "cwe": route[1] if route else None, "raw": raw, "relative": rel})
    return manifest, items


def configure(root, routes):
    """Load existing analyzers and run their frozen SQL checks; no services."""
    names = {"path": "path_triage_v2", "command": "command_triage_v2"}
    files = set(SQL_FILES if "sql" in routes else ())
    files.update(names[r] + ".py" for r in routes if r in names)
    if "command" in routes:
        files.add("command_guard_replay_v1.py")
    missing = sorted(f for f in files if not (root / f).is_file())
    if missing:
        raise ValueError("Thiếu module hiện có: " + ", ".join(missing))
    modules, config = {}, {}
    for route in sorted(routes):
        if route == "sql":
            module = importlib.import_module("master_pipeline_combined_v1")
            argv = sys.argv
            try:
                sys.argv = ["master_pipeline_combined_v1.py", "--check"]
                if module.main() != 0:
                    raise ValueError("SQL --check chưa thành công.")
            finally:
                sys.argv = argv
            if module.audit.sha(Path(module.core.__file__).read_bytes()) != module.audit.CORE_HASH:
                raise ValueError("SQL core khác bản đã kiểm tra.")
            if module.base.BASELINE["model_digest"] != module.audit.DIGEST:
                raise ValueError("Digest baseline SQL không khớp.")
            for rule, (kind, _) in RULES.items():
                if kind == "sql" and not module.pipeline.get_cwe_info(rule)["supported"]:
                    raise ValueError("SQL registry cũ không hỗ trợ " + rule)
            module.pipeline.SQL_NO_FLOW_FALLBACK = True
            # ask_integrated rebuilds requests from numbered Java only; CPG text
            # remains an artifact/gate and is not part of any SQL model request.
            module.pipeline.SQL_SIZE_GATE_SOURCE_ONLY = True
            module.pipeline.ask_ollama_local = module.integrated.ask_integrated
            module.pipeline.analyze_issue = module.base.analyze_issue
            module.pipeline.PROMPT_VERSION = module.VERSION
            config[route] = {"sql_gate_version": "sql-no-flow-gate-v1", "no_flow_fallback": True,
                "size_gate": {"version": "sql-source-size-v2", "source_limit_chars": 10000,
                              "cpg_counted": False, "token_checks": "unchanged_in_each_model_stage"},
                "version": module.VERSION, "model": module.core.MODEL,
                "expected_digest": module.audit.DIGEST,
                "stage1_template": module.base.TEMPLATE, "questions": module.base.QUESTIONS,
                "stage2_request": module.base.v6.make_request(module.core.make_request("1: sample", 1), "draft"),
                "source_audit_version": module.integrated.source_v4.VERSION,
                "source_max_calls": module.integrated.source_v4.MAX_CALLS,
                "source_request": module.integrated.source_request("1: sample", 1)}
        else:
            module = importlib.import_module(names[route])
            if route == "command":
                module.load_static_guard()
            config[route] = {"version": module.VERSION, "model": module.MODEL,
                             "options": module.OPTIONS}
        modules[route] = module
    # Record the actual installed dependencies, not an assumed old copy.
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and Path(path).suffix == ".py" and Path(path).resolve().parent == root:
            files.add(Path(path).name)
    if len({c["model"] for c in config.values()}) > 1:
        raise ValueError("Các nhánh đang dùng model khác nhau.")
    return modules, config, {f: sha((root / f).read_bytes()) for f in sorted(files)}


def context_for(collection, items, config, code):
    return {"version": VERSION, "script_sha256": sha(Path(__file__).read_bytes()),
            "collection": str(collection),
            "collection_manifest_sha256": sha((collection / "manifest.json").read_bytes()),
            "collection_issues_sha256": sha((collection / "issues.json").read_bytes()),
            "config_sha256": fingerprint(config), "dependency_sha256": code,
            "items": [{"index": i["index"], "issue": i["issue"], "route": i["route"],
                       "source_sha256": sha(i["raw"]) if i["raw"] is not None else None} for i in items]}


def service_identity(modules, config):
    if not modules:
        return {"model_digest": None, "joern_image_id": None}
    # Use the stdlib transport of either pilot, or requests in the SQL core.
    pilot = modules.get("path") or modules.get("command")
    if pilot:
        tags = pilot.api("/api/tags")
        image_data = pilot.command(["docker", "image", "inspect", os.getenv("JOERN_IMAGE", "ghcr.io/joernio/joern:nightly")], 30)
    else:
        import subprocess
        import requests
        r = requests.get(os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/") + "/api/tags", timeout=(5, 10))
        r.raise_for_status()
        tags = r.json()
        image_data = subprocess.check_output(["docker", "image", "inspect", os.getenv("JOERN_IMAGE", "ghcr.io/joernio/joern:nightly")], timeout=30, text=True)
    model = next(iter(config.values()))["model"]
    digest = next((m.get("digest") for m in tags["models"] if m.get("name") == model), None)
    if not digest:
        raise ValueError("Chưa có model " + model)
    if "sql" in config and digest != config["sql"]["expected_digest"]:
        raise ValueError("Model digest khác baseline SQL; dừng trước khi gọi AI.")
    return {"model": model, "model_digest": digest, "joern_image_id": json.loads(image_data)[0]["Id"],
            "ollama_url": os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")}


def normalize(row, item):
    result = copy.deepcopy(row)
    result["analysis_route"] = item["route"]
    result["router_version"] = VERSION
    result.setdefault("ai_verdict", result.get("verdict") if result.get("processing_status") in ("AI_PROPOSED", "ANALYZED") else None)
    result.setdefault("combined_verdict", result["verdict"])
    result.setdefault("decision_origin", "AI_PIPELINE" if item["route"] else "RULE_NOT_SUPPORTED")
    for key in ("explanation", "evidence_lines", "missing_context", "decision_basis"):
        result.setdefault("ai_" + key, copy.deepcopy(result.get(key)))
    result.setdefault("requires_review", bool(item["route"]))
    result.setdefault("reviewed_verdict", None)
    result.setdefault("review_status", "PENDING" if item["route"] else None)
    if result.get("processing_status") == "ANALYZED":
        result["processing_status"] = "AI_PROPOSED"
    return result


def dispatch(item, modules, manifest, snapshot, output, image):
    issue, route = item["issue"], item["route"]
    if not route:
        return normalize({"issue_id": issue["key"], "rule": issue.get("rule"),
            "component": issue.get("component"), "line": issue.get("line"),
            "verdict": "UNKNOWN", "processing_status": "SKIPPED", "error_kind": "UNSUPPORTED_RULE",
            "explanation": "Rule nằm ngoài phạm vi ba nhánh đã tích hợp.",
            "evidence_lines": [], "missing_context": []}, item)
    folder = output / f"issue-{item['index']:04d}"
    module = modules[route]
    if route == "sql":
        # SQL creates its own artifact dir and reads only the frozen snapshot.
        row = module.base.analyze_issue(issue, manifest["project"], snapshot, output, image, item["index"])
    else:
        folder.mkdir()
        row = module.analyze(issue, item["raw"], folder, image)
    return normalize(row, item)


def validate_row(row, item, output):
    if not isinstance(row, dict) or row.get("issue_id") != item["issue"]["key"] or row.get("rule") != item["issue"].get("rule"):
        raise ValueError("Checkpoint không khớp cảnh báo.")
    if item["route"]:
        if row.get("source_sha256") != sha(item["raw"]):
            raise ValueError("Checkpoint không khớp hash nguồn.")
        expected = f"issue-{item['index']:04d}"
        if row.get("artifact_dir") != expected or (output / expected / "source.java.txt").read_bytes() != item["raw"]:
            raise ValueError("Artifact không khớp checkpoint.")


def execute(root, collection, old, items, modules, config, context, retry=False):
    output = root / "runs" / ("multi-" + collection.name + "-" + fingerprint(context)[:12])
    output.mkdir(parents=True, exist_ok=True)
    print("KẾT QUẢ:", output, flush=True)
    with (output / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cp = output / "context.json"
        if cp.exists() and read(cp) != context:
            raise ValueError("Context đã thay đổi; không ghi đè.")
        save(cp, context)
        snapshot = output / "source_snapshot"
        cached = {}
        for item in items:
            idx = item["index"]
            if item["raw"] is not None:
                p = snapshot / item["relative"]
                p.parent.mkdir(parents=True, exist_ok=True)
                if p.exists() and p.read_bytes() != item["raw"]:
                    raise ValueError("Snapshot nguồn đã bị thay đổi.")
                if not p.exists():
                    p.write_bytes(item["raw"])
            checkpoint = output / "checkpoints" / f"{idx:04d}.json"
            if checkpoint.exists():
                saved = read(checkpoint)
                row = saved["row"]
                if saved.get("context_sha256") != fingerprint(context) or saved.get("row_sha256") != fingerprint(row):
                    raise ValueError("Checkpoint không khớp context hoặc nội dung.")
                validate_row(row, item, output)
                cached[idx] = row
            else:
                folder = output / f"issue-{idx:04d}"
                if folder.exists():
                    if not retry:
                        raise ValueError(f"Cảnh báo {idx} dở dang. Dùng --retry-incomplete để lưu riêng bản dở và chạy lại riêng cảnh báo này.")
                    archive = output / "interrupted"
                    archive.mkdir(exist_ok=True)
                    import uuid
                    folder.rename(archive / (folder.name + "-" + uuid.uuid4().hex[:12]))
        pending = [i for i in items if i["index"] not in cached]
        identity_path = output / "runtime.json"
        if any(i["route"] for i in pending):
            identity = service_identity(modules, config)
            if identity_path.exists() and read(identity_path) != identity:
                raise ValueError("Model/Joern/Ollama khác lần bắt đầu; không trộn checkpoint.")
            save(identity_path, identity)
        else:
            identity = read(identity_path) if identity_path.exists() else {"joern_image_id": None}
        manifest_path = output / "manifest.json"
        manifest = read(manifest_path) if manifest_path.exists() else {
            "started_at": stamp(), "analysis_id": old["analysis_id"], "project": old["project"],
            "pipeline_version": VERSION, "parent_run": str(collection),
            "source_hashes": {i["relative"]: sha(i["raw"]) for i in items if i["raw"] is not None},
            "evaluation_scope": "selected_supported_components" if context.get("selection") else "collection",
            "selected_components": context.get("selection", []),
            "issue_count": len(items), "supported_issue_count": sum(bool(i["route"]) for i in items),
            "prompt_versions": {k: c["version"] for k, c in config.items()},
            "limitations": ["Uses saved Sonar issues; does not rescan. Only explicitly routed rules.",
                "Single-file context; SQL JDBC, Path File(String) read, and bounded direct exec only.",
                "AI and static rules are proposals; human review is separate. No automatic issue closure.",
                "Resume is per completed issue, not per AI stage. Partial retry can repeat calls.",
                "Prior standalone runs and their human reviews are not imported."]}
        save(output / "issues.json", {"issues": [i["issue"] for i in items], "total": len(items)})
        results = []
        manifest.update(state="IN_PROGRESS", error=None, runtime=identity)
        save(manifest_path, manifest)
        try:
            for position, item in enumerate(items, 1):
                idx = item["index"]
                print(f"[{position}/{len(items)}] {item['route'] or 'SKIP'} | {item['issue'].get('component')}", flush=True)
                if idx in cached:
                    row = cached[idx]
                    print("  Đã lưu: không gọi lại AI.", flush=True)
                else:
                    row = dispatch(item, modules, old, snapshot, output, identity.get("joern_image_id"))
                    validate_row(row, item, output)
                    if item["route"]:
                        save(output / row["artifact_dir"] / "result.json", row)
                    save(output / "checkpoints" / f"{idx:04d}.json", {
                        "context_sha256": fingerprint(context), "row_sha256": fingerprint(row), "row": row})
                results.append(row)
                save(output / "ai_results.json", results)
                print(f"  AI={row['ai_verdict']} | Hệ thống={row['combined_verdict']} | {row['processing_status']}", flush=True)
            errors = [r for r in results if r.get("processing_status") == "ERROR"]
            manifest.update(state="FAILED" if errors else "COMPLETED", result_count=len(results),
                error="Có lỗi xử lý; xem artifact. Chạy lại giữ nguyên lỗi đã lưu." if errors else None,
                verdict_counts=dict(Counter(r["combined_verdict"] for r in results)),
                processing_status_counts=dict(Counter(r["processing_status"] for r in results)), finished_at=stamp())
            save(manifest_path, manifest)
            print("FILE CẦN GỬI:", output / "ai_results.json")
            return 1 if errors else 0
        except BaseException:
            manifest.update(state="IN_PROGRESS", result_count=len(results), error="Lượt chưa hoàn tất; checkpoint đã lưu được giữ lại.")
            save(manifest_path, manifest)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-run", required=True, type=Path)
    parser.add_argument("--check", action="store_true", help="Offline: chỉ kiểm tra, không gọi dịch vụ/ghi kết quả.")
    parser.add_argument("--retry-incomplete", action="store_true", help="Cho phép chạy lại riêng cảnh báo dở dang; lưu bản dở vào interrupted/.")
    parser.add_argument("--only-component", action="append", default=[],
                        help="Exact Sonar component; repeat to run a selected subset.")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if Path(__file__).resolve().parent != root:
        raise ValueError("Đặt script cùng các module và chạy từ ~/AI_sec_tool.")
    collection = args.from_run.resolve()
    old, items = prepare(root, collection)
    if args.only_component:
        selected = set(args.only_component)
        available = {i["issue"].get("component") for i in items if i["route"]}
        if selected - available:
            raise ValueError("Component không có cảnh báo được hỗ trợ: " + ", ".join(sorted(selected - available)))
        items = [i for i in items if i["route"] and i["issue"].get("component") in selected]
        print("LƯỢT CON: chỉ xử lý cảnh báo được hỗ trợ của các component đã chọn.")
    routes = {i["route"] for i in items if i["route"]}
    modules, config, code = configure(root, routes)
    if "command" in modules and hasattr(modules["command"], "configure_context"):
        config["command"]["input_context"] = modules["command"].configure_context(
            collection, [(i["issue"], i["raw"]) for i in items if i["route"] == "command"])
    context = context_for(collection, items, config, code)
    context["selection"] = sorted(set(args.only_component))
    counts = Counter(i["route"] or "SKIPPED" for i in items)
    print("ĐỊNH TUYẾN:", dict(counts), flush=True)
    print("Giới hạn lượt AI mới:", counts["sql"] * 4 + counts["path"] * 2 + counts["command"] * getattr(modules.get("command"), "MAX_MODEL_CALLS_PER_ISSUE", 2), "(ít hơn nếu bỏ qua hoặc có checkpoint).")
    if args.check:
        print("MULTI_CHECK_OK: cấu hình và hash nguồn hợp lệ; chưa gọi SonarQube/Joern/AI, chưa tạo lượt chạy.")
        return 0
    return execute(root, collection, old, items, modules, config, context, args.retry_incomplete)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Đã dừng. Giữ checkpoint; cảnh báo dở cần --retry-incomplete.")
        sys.exit(130)
    except Exception as exc:
        message = str(exc)
        token = os.getenv("SONAR_TOKEN")
        if token:
            message = message.replace(token, "[REDACTED]")
        print("LỖI:", message, file=sys.stderr)
        sys.exit(1)
