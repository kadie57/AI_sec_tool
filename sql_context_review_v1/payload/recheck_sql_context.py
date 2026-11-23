"""Reanalyze all SQL alerts in a saved source-review run with pinned helpers.

Run from ~/AI_sec_tool. --check is offline/no writes. --run calls local Ollama.
The default is the eight-alert diagnostic already reviewed, not a fresh holdout.
No SonarQube, Joern or Java execution; previous results are immutable inputs.
"""
import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sys
import zipfile

import remerge_sql_sources as previous_reader
import sql_context_bundle_v1 as contexts
import sql_context_triage_v1 as triage

VERSION = "sql-context-recheck-v1"
DEFAULT = previous_reader.DEFAULT
DEPENDENCIES = ("sql_context_bundle_v1.py", "sql_context_triage_v1.py", "recheck_sql_context.py")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_hash(path):
    return contexts.sha(path.read_bytes())


def prepare(root, previous, repository):
    # Reuse checked provenance/merge policy, but NONE of these facts enter prompts.
    old_plan, old_provenance = previous_reader.prepare(root, previous)
    before_rows = previous_reader.recompute(old_plan)
    source_context = read(previous / "context.json")
    initial = root / "runs" / Path(source_context["previous_run"]).name
    if file_hash(initial / "context.json") != source_context["previous_context_sha256"]:
        raise ValueError("Context lượt SQL gốc không khớp lượt source audit.")
    initial_context = read(initial / "context.json")
    collection = root / "runs" / Path(initial_context["collection"]).name
    if (file_hash(collection / "manifest.json") != initial_context["collection_manifest_sha256"]
            or file_hash(collection / "issues.json") != initial_context["collection_issues_sha256"]):
        raise ValueError("Lượt thu thập SonarQube không khớp nguồn đầu vào đã lưu.")
    manifest = read(collection / "manifest.json")
    inventory = manifest["source_hashes"]
    issues = read(collection / "issues.json")
    if isinstance(issues, dict):
        issues = issues["issues"]
    issue_by_key = {i["key"]: i for i in issues}
    repository = repository.expanduser().resolve()
    repo = contexts.Repository(repository, manifest["benchmark_commit"])
    items = []
    for old, row in zip(old_plan, before_rows):
        issue = issue_by_key.get(row["issue_id"])
        if not issue or any(issue.get(k) != row.get(k) for k in ("rule", "component", "line")):
            raise ValueError("Cảnh báo không khớp lượt SonarQube gốc.")
        rel = row["component"].split(":", 1)[1]
        if inventory.get(rel) != row["source_sha256"]:
            raise ValueError("Nguồn không khớp inventory thu thập.")
        marker = "/src/main/java/"
        if marker not in "/" + rel:
            raise ValueError("Không xác định được đường dẫn source trong repository.")
        java_path = "src/main/java/" + ("/" + rel).split(marker, 1)[1]
        raw = (old["folder"] / "source.java.txt").read_bytes()
        bundle = contexts.build(repo, java_path, raw)
        if f"F0:{row['line']}" not in contexts.references(bundle):
            raise ValueError("Dòng cảnh báo không phải dòng bằng chứng JDBC hợp lệ.")
        items.append({"row": row, "bundle": bundle, "issue": issue,
            "context_sha256": contexts.fingerprint(bundle),
            "request_sha256": {s: contexts.fingerprint(triage.make_request(s, bundle, row["line"])) for s in ("source", "sql")}})
    provenance = {"version": VERSION, "triage_version": triage.VERSION, "context_version": contexts.VERSION,
        "previous_run": str(previous), "previous_provenance": old_provenance,
        "collection": str(collection), "collection_manifest_sha256": file_hash(collection / "manifest.json"),
        "benchmark_commit": repo.commit, "repository": str(repository),
        "model": triage.core.MODEL, "model_digest": triage.DIGEST, "options": triage.OPTIONS,
        "dependency_sha256": {n: file_hash(root / n) for n in DEPENDENCIES},
        "selection": "All SQL alerts in the supplied saved source-review run; no label-based selection",
        "reference_labels_loaded": False, "independent_holdout": False,
        "old_model_answers_in_prompts": False, "sql_effect_recomputed": True,
        "maximum_new_calls_per_issue": 4,
        "items": [{"issue_id": p["row"]["issue_id"], "artifact_dir": p["row"]["artifact_dir"],
                   "source_sha256": p["row"]["source_sha256"], "context_sha256": p["context_sha256"],
                   "request_sha256": p["request_sha256"],
                   "helper_hashes": {f["path"]: f["sha256"] for i, f in p["bundle"]["files"].items() if i != "F0"}}
                  for p in items]}
    return items, provenance


def row_for(item, source, sql):
    old = item["row"]
    result = triage.combine(source, sql, item["bundle"], old["line"])
    row = {k: old[k] for k in ("issue_id", "rule", "component", "line", "source_sha256", "artifact_dir")}
    row.update(result)
    row.update(model=triage.core.MODEL, model_digest=triage.DIGEST, analysis_route="sql",
        prompt_version=triage.VERSION, context_version=contexts.VERSION,
        previous_ai_verdict=old.get("ai_verdict"), previous_combined_verdict=old["combined_verdict"],
        ai_verdict=result["verdict"], combined_verdict=result["verdict"],
        decision_origin="FRESH_SOURCE_AND_SQL_FACTS_WITH_DETERMINISTIC_POLICY",
        review_status="CALL_ERROR" if result.get("error_kind") else "PENDING", reviewed_verdict=None,
        requires_review=True, processing_status="ERROR" if result.get("error_kind") else "AI_PROPOSED",
        context_sha256=item["context_sha256"],
        attempt_count=source.get("attempt_count", 0) + sql.get("attempt_count", 0),
        elapsed_seconds=round(source.get("elapsed_seconds", 0) + sql.get("elapsed_seconds", 0), 3),
        elapsed_scope="saved_new_source_and_sql_calls_only")
    return row


def summarize(output, items, provenance):
    rows = []
    for item in items:
        folder = output / item["row"]["artifact_dir"]
        if not (folder / "result.json").exists():
            continue
        if read(folder / "context_bundle.json") != item["bundle"]:
            raise ValueError("Context đã lưu khác nguồn/helper hiện tại.")
        source, sql = read(folder / "source_review.json"), read(folder / "sql_review.json")
        for stage, record in (("source", source), ("sql", sql)):
            if record.get("error_kind") == "STAGE_NOT_RUN":
                continue
            expected = {"version": triage.VERSION, "stage": stage,
                "context_sha256": item["context_sha256"],
                "request_sha256": item["request_sha256"][stage], "model_digest": triage.DIGEST}
            if record.get("identity") != expected:
                raise ValueError("Danh tính bản phân tích mới không khớp.")
            if not record.get("error_kind"):
                facts, _ = triage.core.parse_model_text(record["raw_output"])
                if facts != record["facts"] or record["ollama_response"].get("response") != record["raw_output"]:
                    raise ValueError("Facts khác đầu ra mô hình đã lưu.")
        recomputed = row_for(item, source, sql)
        if read(folder / "result.json") != recomputed:
            raise ValueError("Kết quả ghép mới khác facts/policy đã lưu.")
        rows.append(recomputed)
    finished = len(rows) == len(items)
    summary = {"version": VERSION, "state": "COMPLETED" if finished else "IN_PROGRESS",
        "planned_count": len(items), "result_count": len(rows),
        "verdict_counts": dict(Counter(r["verdict"] for r in rows)),
        "error_count": sum(bool(r.get("error_kind")) for r in rows),
        "attempts_in_completed_rows": sum(r["attempt_count"] for r in rows),
        "saved_seconds_in_completed_rows": round(sum(r["elapsed_seconds"] for r in rows), 3),
        "changed_combined_count": sum(r["combined_verdict"] != r["previous_combined_verdict"] for r in rows),
        "provenance": provenance, "review_required": True,
        "limitations": ["Post-evaluation diagnostic on previously inspected cases; not a new held-out accuracy result.",
            "Cross-file references and API anchors are checked; model semantic claims still require review.",
            "No interprocedural Joern traversal is added; helpers come from a bounded static source inventory.",
            "Previous AI results and human reviews are not overwritten; no SonarQube issue is closed.",
            "Context size/options and prompts changed; this run alone does not isolate the effect of any one change."]}
    triage.save(output / "ai_results.json", rows)
    triage.save(output / "summary.json", summary)
    return summary


def bundle_output(output):
    dest = output.parent / (output.name + "-review.zip")
    tmp = dest.with_suffix(".zip.tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for p in sorted(output.rglob("*")):
            if p.is_file() and not p.is_symlink() and p.name != "run.lock" and p.suffix != ".tmp":
                archive.write(p, str(Path(output.name) / p.relative_to(output)))
    tmp.replace(dest)
    print("ZIP CẦN GỬI:", dest, flush=True)


def run(root, items, provenance, retry_incomplete=False):
    output = root / "experiments/sql_context_recheck_v1" / (Path(provenance["previous_run"]).name + "-" + contexts.fingerprint(provenance)[:12])
    output.mkdir(parents=True, exist_ok=True)
    with (output / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = output / "context.json"
        if path.exists():
            if read(path) != provenance:
                raise ValueError("Đầu ra đã thuộc cấu hình khác.")
        elif any(output.glob("issue-*/*")):
            raise ValueError("Có checkpoint nhưng thiếu context.json.")
        else:
            triage.save(path, provenance)
        summary = summarize(output, items, provenance)
        try:
            if summary["result_count"] != len(items) and triage.core.model_digest() != triage.DIGEST:
                raise ValueError("Model/digest khác bản trước; chưa gọi sinh AI.")
            for i, item in enumerate(items, 1):
                folder = output / item["row"]["artifact_dir"]
                print(f"[{i}/{len(items)}] {Path(item['row']['component']).name}", flush=True)
                if (folder / "result.json").exists():
                    print("    Đã lưu, bỏ qua cả hai lượt AI.", flush=True)
                    continue
                folder.mkdir(exist_ok=True)
                triage.save(folder / "context_bundle.json", item["bundle"])
                triage.save(folder / "previous_result.json", item["row"])
                triage.save(folder / "issue.json", item["issue"])
                (folder / "source.java.txt").write_text(item["bundle"]["files"]["F0"]["source"], encoding="utf-8")
                print("    1/2: phân tích nguồn và giá trị sau helper/nhánh...", flush=True)
                source = triage.ask("source", item["bundle"], item["row"]["line"], folder / "attempts", retry_incomplete)
                triage.save(folder / "source_review.json", source)
                if source.get("error_kind") in triage.TRANSPORT_ERRORS:
                    skipped = {"error_kind": "STAGE_NOT_RUN", "error": "Bước SQL chưa gọi do lỗi kết nối ở bước nguồn.",
                               "attempt_count": 0, "elapsed_seconds": 0}
                    triage.save(folder / "sql_review.json", skipped)
                    triage.save(folder / "result.json", row_for(item, source, skipped))
                    print("    Dừng sau lỗi kết nối; kết quả lượt gọi đã được lưu.", flush=True)
                    break
                print("    2/2: phân tích lại tác động SQL từ code...", flush=True)
                sql = triage.ask("sql", item["bundle"], item["row"]["line"], folder / "attempts", retry_incomplete)
                triage.save(folder / "sql_review.json", sql)
                row = row_for(item, source, sql)
                triage.save(folder / "result.json", row)
                print(f"    {row['previous_combined_verdict']} -> {row['verdict']} | lỗi: {row.get('error_kind')}", flush=True)
                summary = summarize(output, items, provenance)
                if sql.get("error_kind") in triage.TRANSPORT_ERRORS:
                    print("    Dừng sau lỗi kết nối; không tự thử lại lỗi đã lưu.", flush=True)
                    break
        finally:
            summary = summarize(output, items, provenance)
            print("KẾT QUẢ:", output, flush=True)
            bundle_output(output)
        print(f"Đã lưu {summary['result_count']}/{len(items)} cảnh báo. Kết quả mới vẫn cần đối chiếu code.", flush=True)
        return 0 if summary["state"] == "COMPLETED" and not summary["error_count"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-run", type=Path, default=Path(DEFAULT))
    parser.add_argument("--repository", type=Path,
        default=Path(os.getenv("OWASP_BENCHMARK_ROOT", str(Path.home() / "AI_sec_benchmarks/BenchmarkJava"))))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--retry-incomplete", action="store_true")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if root != Path(__file__).resolve().parent:
        raise ValueError("Chạy từ ~/AI_sec_tool.")
    items, provenance = prepare(root, args.previous_run.resolve(), args.repository)
    for item in items:
        files = item["bundle"]["files"]
        print(f"{Path(item['row']['component']).name}: {len(files)-1} file hỗ trợ; khoảng trống ngữ cảnh: {len(item['bundle']['missing_context'])}")
    print(f"SQL_CONTEXT_CHECK_OK: {len(items)} cảnh báo; nguồn và helper cùng commit; không đọc nhãn tham chiếu.")
    print(f"Phân tích mới: {len(items)*2} lượt AI thông thường, tối đa {len(items)*4} nếu sửa lỗi JSON/bằng chứng; context=8192.")
    if args.check:
        print("Chưa ghi file, chưa gọi AI/SonarQube/Joern.")
        return 0
    return run(root, items, provenance, args.retry_incomplete)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nĐã dừng; checkpoint đã lưu được giữ lại. Lượt chưa lưu cần --retry-incomplete.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print("[LỖI] " + str(exc), file=sys.stderr)
        sys.exit(1)
