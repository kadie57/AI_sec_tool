"""Continue complete-but-invalid ProcessBuilder assessments with one bounded repair.
Uses frozen source/helper/CPG from the selected run. No Sonar or Joern invocation.
Valid previous rows are carried forward with their original prompt version.
An invalid complete JSON can be re-evaluated once; no reference labels are read.
"""
import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import zipfile

import command_triage_v2 as core
import command_processbuilder_v1 as pb

VERSION = "command78-continue-validation-v1"
FILES = ("source.java.txt", "helper_context.json", "execution_guard.json", "cpg_evidence.json",
         "cpg_compact.json", "joern.log", "slice.sc", "llm_source.json", "llm_command.json")


def stamp():
    return datetime.now(timezone.utc).isoformat()


def prepare(parent):
    manifest = core.read(parent / "manifest.json")
    old_context = core.read(parent / "context.json")
    rows = core.read(parent / "ai_results.json")
    bundle = core.read(parent / "issues.json")
    issues = bundle if isinstance(bundle, list) else bundle["issues"]
    if manifest.get("state") not in ("FAILED", "COMPLETED") or not manifest.get("analysis_id"):
        raise ValueError("Cần lượt đã dừng/hoàn tất và có analysis_id.")
    if not isinstance(rows, list) or len(rows) > 6 or not rows or len(rows) != len(issues):
        raise ValueError("Lượt tiếp tục này cần tối đa 6 cảnh báo ProcessBuilder, đủ bản ghi.")
    index = {i["key"]: i for i in issues}
    if len(index) != len(issues) or len({r["issue_id"] for r in rows}) != len(rows):
        raise ValueError("Key cảnh báo trùng.")
    plan = []
    for row in rows:
        issue = index[row["issue_id"]]
        if issue.get("rule") != core.RULE or not pb.is_candidate(issue):
            raise ValueError("Lượt này có cảnh báo ngoài ProcessBuilder; không tự chọn lại mẫu.")
        rel = row.get("artifact_dir", "")
        if not rel or Path(rel).name != rel:
            raise ValueError("artifact_dir không hợp lệ.")
        folder = (parent / rel).resolve()
        if not folder.is_relative_to(parent):
            raise ValueError("Artifact nằm ngoài lượt nguồn.")
        raw = (folder / "source.java.txt").read_bytes()
        if core.sha(raw) != row["source_sha256"]:
            raise ValueError("Mã nguồn không khớp kết quả cũ.")
        context = core.read(folder / "helper_context.json")
        if context.get("caller_sha256") != core.sha(raw) or core.fingerprint(context) != row.get("helper_context_sha256"):
            raise ValueError("Helper context không khớp fingerprint đã lưu.")
        recorded = old_context.get("processbuilder", {}).get("sources", {}).get(issue["key"], {})
        if recorded.get("context_sha256") != core.fingerprint(context) or recorded.get("caller_sha256") != core.sha(raw):
            raise ValueError("Context nguồn không khớp manifest cấu hình.")
        for ident, helper in context["files"].items():
            if helper.get("file_id") != ident or core.sha(helper["source"].encode("utf-8")) != helper["sha256"]:
                raise ValueError("Nguồn helper khác hash đã lưu.")
        source = raw.decode("utf-8")
        guard = pb.recognize(source, issue)
        if not guard["supported"] or core.read(folder / "execution_guard.json") != guard:
            raise ValueError("Nhận dạng API khác kết quả đã lưu.")
        compact, _ = pb.select_evidence(core.read(folder / "cpg_evidence.json"), guard)
        if core.read(folder / "cpg_compact.json") != compact:
            raise ValueError("CPG rút gọn không khớp bằng chứng đầy đủ.")
        # Require byte-equivalent semantic requests, not merely same issue names.
        saved = {}
        for stage in ("source", "command"):
            path = folder / ("llm_" + stage + ".json")
            if path.exists():
                value = core.read(path)
                if value.get("request_payload") != pb.make_request(core, stage, source, issue, context, guard, compact):
                    raise ValueError("Yêu cầu AI khác bản nền của cơ chế sửa; không tái sử dụng.")
                if value.get("facts") is not None:
                    pb.validate(value["facts"], stage, source, context)
                saved[stage] = value
        valid = row.get("processing_status") == "AI_PROPOSED" and row.get("error_kind") is None
        if valid:
            if any(s not in saved or saved[s].get("error_kind") or saved[s].get("facts") is None for s in ("source", "command")):
                raise ValueError("Bản ghi hoàn tất thiếu đáp ứng AI hợp lệ.")
            sf, cf = saved["source"]["facts"], saved["command"]["facts"]
            if row.get("model_assessment") != {"source": sf, "command": cf} or pb.decide(sf, cf, context)[0] != row["verdict"]:
                raise ValueError("Nhãn/facts đã lưu không khớp các bước AI.")
            calls = 0
        else:
            stage = "source" if "source" not in saved or saved["source"].get("error_kind") else "command"
            failed = saved.get(stage)
            if failed is None or pb.repair_candidate(failed, stage, source, context) is None:
                raise ValueError("Lỗi không thuộc dạng JSON hoàn tất nhưng bị validator từ chối; không gọi lại tự động.")
            if any((folder / ("llm_" + s + "_repair.json")).exists() for s in ("source", "command")):
                raise ValueError("Lượt nguồn đã sửa một lần; không lặp vô hạn.")
            calls = 1 + (2 if stage == "source" else 0)
        files = {name: core.sha((folder / name).read_bytes()) for name in FILES if (folder / name).is_file()}
        plan.append({"issue": issue, "raw": raw, "row": row, "helper_context": context,
                     "folder": folder, "copy_hashes": files, "reuse": valid, "max_new_calls": calls})
    return manifest, old_context, plan


def copy_artifacts(item, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name, digest in item["copy_hashes"].items():
        src = item["folder"] / name
        dst = destination / name
        if core.sha(src.read_bytes()) != digest:
            raise ValueError("Artifact lượt nguồn vừa thay đổi; dừng.")
        if dst.exists():
            if core.sha(dst.read_bytes()) != digest:
                raise ValueError("Artifact sao chép khác checkpoint nguồn.")
        else:
            shutil.copy2(src, dst)


def package(output):
    dest = output / "command_processbuilder_results.zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(output.rglob("*")):
            relative = path.relative_to(output)
            if path.is_file() and not {"input", "workspace"}.intersection(relative.parts) and path.suffix in (".json", ".txt", ".log", ".sc"):
                z.write(path, relative.as_posix())
    return dest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-run", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    parent = args.from_run.expanduser().resolve()
    old, original_context, plan = prepare(parent)
    limit = sum(p["max_new_calls"] for p in plan)
    for p in plan:
        print(p["issue"]["component"].rsplit("/", 1)[-1], "|", "giữ kết quả đã có" if p["reuse"] else "sửa JSON chưa hợp lệ và chạy phần còn thiếu")
    print(f"Tối đa {limit} lượt gọi AI mới. Dùng nguồn/helper/CPG đã lưu; không chạy SonarQube hoặc Joern.")
    if args.check:
        print("REPAIR_CHECK_OK: dữ liệu và yêu cầu nền khớp; chưa gọi AI, chưa ghi kết quả.")
        return 0
    config = {"version": VERSION, "processbuilder_version": pb.VERSION,
              "parent_run": str(parent), "analysis_id": old["analysis_id"],
              "parent_context_sha256": core.sha((parent / "context.json").read_bytes()),
              "parent_results_sha256": core.sha((parent / "ai_results.json").read_bytes()),
              "model": core.MODEL, "model_digest": original_context["model_digest"],
              "joern_image_id_reused": original_context["joern_image_id"],
              "options": pb.OPTIONS, "ollama_url": os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
              "code_sha256": {Path(m.__file__).name: core.sha(Path(m.__file__).read_bytes()) for m in (core, pb)},
              "runner_sha256": core.sha(Path(__file__).read_bytes()),
              "items": [{"issue_id": p["issue"]["key"], "reuse": p["reuse"], "artifacts": p["copy_hashes"]} for p in plan]}
    output = parent.parent / (parent.name + "-repair-" + core.fingerprint(config)[:12])
    output.mkdir(parents=True, exist_ok=True)
    with (output / "run.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Lượt tiếp tục đang chạy ở terminal khác.") from None
        if (output / "context.json").exists() and core.read(output / "context.json") != config:
            raise ValueError("Context khác checkpoint; không ghi đè.")
        pending = [p for p in plan if not p["reuse"] and not (output / p["row"]["artifact_dir"] / "result.json").exists()]
        if pending:
            digest = next((m["digest"] for m in core.api("/api/tags")["models"] if m.get("name") == core.MODEL), None)
            if digest != config["model_digest"]:
                raise ValueError("Model khác lượt trước; chưa gọi AI.")
        core.save(output / "context.json", config)
        core.save(output / "issues.json", {"issues": [p["issue"] for p in plan], "total": len(plan)})
        original_api = core.api
        calls_new = 0
        def counted_api(endpoint, payload=None):
            nonlocal calls_new
            if endpoint == "/api/generate":
                if calls_new >= limit:
                    raise ValueError("Đã chạm giới hạn lượt gọi AI mới.")
                calls_new += 1
            return original_api(endpoint, payload)
        report = core.read(output / "manifest.json") if (output / "manifest.json").exists() else {
            "started_at": stamp(), "analysis_id": old["analysis_id"], "project": old["project"],
            "parent_run": str(parent), "pipeline_version": VERSION, "prompt_version": pb.VERSION,
            "source_hashes": old.get("source_hashes", {}), "benchmark_commit": old.get("benchmark_commit"),
            "issue_count": len(plan), "supported_issue_count": len(plan), "generation_calls_new": 0,
            "reuse_policy": "Valid parent rows retain original prompt version and timings; repaired rows record their initial reused responses.",
            "limitations": ["Same development cases, not independent evaluation.", "Valid citations do not prove reasoning; human review required.",
                            "No automatic issue closure, no labels provided to generation."]}
        report.update(state="IN_PROGRESS", error=None)
        core.save(output / "manifest.json", report)
        results = []
        core.api = counted_api
        try:
            for p in plan:
                folder = output / p["row"]["artifact_dir"]
                dest = folder / "result.json"
                if dest.exists():
                    result = core.read(dest)
                    if result.get("issue_id") != p["issue"]["key"] or result.get("source_sha256") != core.sha(p["raw"]):
                        raise ValueError("Checkpoint không khớp mẫu.")
                else:
                    copy_artifacts(p, folder)
                    if p["reuse"]:
                        result = copy.deepcopy(p["row"])
                    else:
                        pb.CONTEXTS[core.sha(p["raw"])] = copy.deepcopy(p["helper_context"])
                        result = core.analyze(p["issue"], p["raw"], folder, original_context["joern_image_id"])
                    result["continuation"] = {"parent_run": str(parent), "mode": "REUSED_VALID_RESULT" if p["reuse"] else "VALIDATION_REPAIR",
                                              "parent_row_sha256": core.fingerprint(p["row"]),
                                              "cpg_reused": True, "helper_context_reused": True}
                    core.save(dest, result)
                results.append(result)
                core.save(output / "ai_results.json", results)
                print(result["component"].rsplit("/", 1)[-1], "|", result["verdict"], "|", result.get("error_kind"))
            failed = any(r.get("error_kind") for r in results)
            report.update(state="FAILED" if failed else "COMPLETED", error="Còn lỗi; xem artifact." if failed else None,
                          result_count=len(results), verdict_counts=dict(Counter(r["verdict"] for r in results)),
                          processing_status_counts=dict(Counter(r["processing_status"] for r in results)), finished_at=stamp())
        finally:
            core.api = original_api
            report["generation_calls_new"] = report.get("generation_calls_new", 0) + calls_new
            core.save(output / "manifest.json", report)
            print("ZIP CẦN GỬI:", package(output))
        return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nĐã dừng. Các attempt đã lưu được giữ nguyên; chạy lại cùng lệnh để tiếp tục.")
        sys.exit(130)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("[LỖI]", exc, file=sys.stderr)
        sys.exit(1)
