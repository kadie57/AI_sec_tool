"""Replay only source review using saved SQL stages. No labels, Sonar or Joern.

--check is offline. --run makes one source call per issue, at most one repair
for malformed JSON/evidence. Saved attempts (including failures) are reused.
"""
import argparse
import copy
import fcntl
import json
from pathlib import Path
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
import zipfile

import triage_v5 as core
import source_audit_v2 as audit
import sql_source_audit_v4 as review
import run_holdout_system as masking
from replay_source_merge import merge_assessments

VERSION = "sql-source-recheck-v1"
DEFAULT_RUN = "runs/multi-owasp-holdout-20261115T151839Z-b04660-688bdde398e1"
EXPECTED_PATCHES = {'sql_source_audit_v4.py': '2f8926f8cc545be46ba4946e35bca958685116acd0e986fd28f1b18731341458', 'master_pipeline_source_v1.py': 'efe2078caa8ca90ab912e97362cf8b046ff12b12aa117a564f555ca6f7563246', 'master_pipeline_combined_v1.py': '08c2f2a78bb9a9fd38361a764b852f641c8748e0ec2668fd13398217fb5ceab8', 'replay_source_merge.py': '9cdc928eb0c9759e834639383e8960c0dde3761e226249806539293adf4a3ad2', 'master_pipeline_multi_v1.py': '69c753d064f4921afda2465e69f5d6ba2032d5e81ecb35f55d2c0be0f69d8398'}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_hash(path):
    return audit.sha(path.read_bytes())


def prepare(root, previous):
    context = read(previous / "context.json")
    rows = read(previous / "ai_results.json")
    manifest = read(previous / "manifest.json")
    if (manifest.get("state") not in ("COMPLETED", "FAILED")
            or not isinstance(rows, list) or not rows or manifest.get("result_count") != len(rows)):
        raise ValueError("Lượt trước chưa xử lý xong hoặc không có kết quả đầy đủ.")
    runtime = manifest.get("runtime", {})
    if runtime.get("model") != core.MODEL or runtime.get("model_digest") != audit.DIGEST:
        raise ValueError("Model/digest của lượt trước không khớp.")
    if file_hash(Path(core.__file__)) != audit.CORE_HASH or not EXPECTED_PATCHES:
        raise ValueError("Core v5 hoặc gói cập nhật không hợp lệ.")
    for name, expected in {**context["dependency_sha256"], **EXPECTED_PATCHES}.items():
        if Path(name).name != name or file_hash(root / name) != expected:
            raise ValueError("Module khác bản đã kiểm tra: " + name)
    policy = context.get("evaluation_input_policy", {})
    if (policy.get("version") != masking.VERSION
            or policy.get("script_sha256") != file_hash(Path(masking.__file__))
            or policy.get("source_policy") != "mask_all_java_comments_keep_lines"):
        raise ValueError("Không khớp chính sách che chú thích của lượt trước.")
    plan, seen = [], set()
    by_id = {x["issue"]["key"]: x for x in context["items"]}
    for row in rows:
        if row.get("analysis_route") != "sql":
            continue
        key = row.get("issue_id")
        if not isinstance(key, str) or not key or key in seen:
            raise ValueError("Thiếu hoặc trùng issue_id SQL.")
        seen.add(key)
        item = by_id.get(key)
        if (not item or item["route"] != "sql"
                or any(row.get(k) != item["issue"].get(k) for k in ("line", "component", "rule"))):
            raise ValueError("Cảnh báo không khớp context của lượt trước.")
        artifact = row.get("artifact_dir")
        if not isinstance(artifact, str) or Path(artifact).name != artifact:
            raise ValueError("Thiếu/không hợp lệ artifact_dir SQL.")
        folder = (previous / artifact).resolve()
        if not folder.is_relative_to(previous):
            raise ValueError("Artifact ra ngoài thư mục lượt trước.")
        raw = (folder / "source.java.txt").read_bytes()
        if audit.sha(raw) != row.get("source_sha256") or audit.sha(raw) != item["source_sha256"]:
            raise ValueError("Nguồn artifact khác lần quét: " + artifact)
        source = raw.decode("utf-8")
        stage = read(folder / "llm_stage2.json")
        body, req = stage.get("ollama_response", {}), stage.get("request_payload", {})
        if (stage.get("error_kind") or body.get("done") is not True or body.get("done_reason") == "length"
                or stage.get("decision_policy_version") != core.PROMPT_VERSION):
            raise ValueError("Bước SQL trước chưa hoàn tất hợp lệ: " + artifact)
        if (req.get("model") != core.MODEL or req.get("system") != core.SYSTEM_PROMPT
                or req.get("options") != core.OPTIONS or req.get("format") != core.SCHEMA):
            raise ValueError("Request SQL cũ khác cấu hình đã kiểm tra.")
        n = body.get("prompt_eval_count")
        if type(n) is not int or n + core.OPTIONS["num_predict"] >= core.OPTIONS["num_ctx"]:
            raise ValueError("Bước SQL cũ thiếu ngân sách ngữ cảnh hợp lệ.")
        parsed, _ = core.parse_model_text(body["response"])
        if parsed != stage["model_assessment"] or body["response"] != stage["raw_output"]:
            raise ValueError("Facts SQL không khớp đầu ra nguyên bản.")
        checked = core.validate_and_decide(parsed, len(source.splitlines()))
        if checked["error_kind"] or checked["verdict"] != stage["verdict"]:
            raise ValueError("Nhãn SQL cũ khác chính sách v5.")
        expected = "\n".join(f"{i}: {s}" for i, s in enumerate(masking.mask_java(source).splitlines(), 1))
        sent = copy.deepcopy(req)
        count, _ = masking.sanitize(sent)
        if count != 1 or not sent["prompt"].startswith(f"Thẩm định SQL injection tại dòng {row['line']}."):
            raise ValueError("Sai dòng hoặc có nhiều khối nguồn trong request SQL cũ.")
        blocks = masking.BLOCK.findall(sent["prompt"])
        if blocks[0][1] != expected:
            raise ValueError("Nguồn trong request SQL cũ không khớp artifact.")
        request = review.make_request(expected, row["line"], parsed["missing_context"])
        plan.append({"row": row, "folder": folder, "source": source, "stage": stage, "request": request,
            "stage2_sha256": file_hash(folder / "llm_stage2.json"), "request_sha256": review.fingerprint(request)})
    if not plan:
        raise ValueError("Không có cảnh báo SQL với bước 2 hợp lệ để đối chiếu.")
    provenance = {"version": VERSION, "source_audit_version": review.VERSION,
        "previous_run": str(previous), "previous_context_sha256": file_hash(previous / "context.json"),
        "previous_results_sha256": file_hash(previous / "ai_results.json"),
        "previous_manifest_sha256": file_hash(previous / "manifest.json"),
        "script_sha256": file_hash(Path(__file__)), "dependency_sha256": EXPECTED_PATCHES,
        "model": core.MODEL, "model_digest": audit.DIGEST,
        "comment_policy": copy.deepcopy(policy), "independent_holdout": False,
        "reference_labels_loaded": False, "selection": "All SQL issues in the supplied saved run",
        "sql_effect_recomputed": False, "maximum_source_calls_per_issue": review.MAX_CALLS,
        "items": [{"issue_id": p["row"]["issue_id"], "source_sha256": p["row"]["source_sha256"],
            "stage2_sha256": p["stage2_sha256"], "request_sha256": p["request_sha256"]} for p in plan]}
    return plan, provenance


def make_result(item, record):
    previous = item["row"]
    if record["error"]:
        merged = core.unknown_result("Kiểm tra nguồn chưa hợp lệ: " + record["error"], "SOURCE_AUDIT_ERROR",
            requires_review=True, decision_basis="SOURCE_AUDIT_FAILED")
    else:
        merged = merge_assessments(item["stage"], record, item["source"])
    row = {k: previous[k] for k in ("issue_id", "rule", "component", "line", "source_sha256", "artifact_dir")}
    row.update(merged)
    row.update({"model": core.MODEL, "analysis_route": "sql", "prompt_version": review.VERSION,
        "verdict": merged["verdict"], "ai_verdict": merged["verdict"], "combined_verdict": merged["verdict"],
        "previous_final_verdict": previous["verdict"], "previous_error_kind": previous.get("error_kind"),
        "stage2_verdict_reused": item["stage"]["verdict"],
        "stage2_sql_effect_reused": item["stage"]["model_assessment"]["sql_effect"],
        "processing_status": "ERROR" if record["error"] else "AI_PROPOSED",
        "source_audit_facts": record["facts"], "source_audit_error_kind": record["error_kind"],
        "source_audit_attempt_count": record["attempt_count"], "gap_reviews": record["gap_reviews"],
        "elapsed_seconds": record["elapsed_seconds"], "elapsed_scope": "saved_source_attempts_only",
        "requires_review": True, "review_status": "PENDING" if not record["error"] else "CALL_ERROR",
        "reviewed_verdict": None, "decision_origin": "REUSED_SQL_AND_NEW_SOURCE_MODEL_REVIEW"})
    return row


def summarize(output, plan, provenance):
    rows = []
    for item in plan:
        path = output / item["row"]["artifact_dir"] / "llm_source_audit.json"
        if path.exists():
            record = read(path)
            if (record.get("request_payload") != item["request"] or record.get("prompt_version") != review.VERSION
                    or record.get("source_sha256") != item["row"]["source_sha256"]
                    or record.get("model_digest") != audit.DIGEST):
                raise ValueError("Kết quả đã lưu khác cấu hình nguồn hiện tại.")
            row = make_result(item, record)
            rows.append(row)
            review.save(path.parent / "result.json", row)
    errors = sum(bool(r.get("error_kind")) for r in rows)
    summary = {"version": VERSION, "state": "COMPLETED" if len(rows) == len(plan) else "IN_PROGRESS",
        "result_count": len(rows), "planned_count": len(plan), "error_count": errors,
        "verdict_counts": dict(Counter(r["verdict"] for r in rows)),
        "source_attempts_saved": sum(r["source_audit_attempt_count"] for r in rows),
        "source_seconds_saved": round(sum(r["elapsed_seconds"] for r in rows), 3),
        "provenance": provenance, "review_required": True,
        "limitations": ["SQL effects are reused, including any reasoning errors.",
            "Line checks and model gap reviews do not prove semantic correctness.",
            "Post-evaluation diagnostic; not a new untouched holdout or a full-system accuracy estimate."]}
    review.save(output / "ai_results.json", rows)
    review.save(output / "summary.json", summary)
    return summary


def bundle(output):
    dest = output.parent / (output.name + "-review.zip")
    temp = dest.with_suffix(".zip.tmp")
    with zipfile.ZipFile(temp, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(output.rglob("*")):
            if p.is_file() and not p.is_symlink() and p.name != "run.lock" and p.suffix != ".tmp":
                z.write(p, str(Path(output.name) / p.relative_to(output)))
    temp.replace(dest)
    print("ZIP CẦN GỬI:", dest, flush=True)


def run(plan, provenance, output, retry_incomplete=False):
    output.mkdir(parents=True, exist_ok=True)
    with (output / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        context_file = output / "context.json"
        if context_file.exists():
            if read(context_file) != provenance:
                raise ValueError("Checkpoint khác cấu hình; không ghi đè.")
        elif any(output.glob("issue-*/llm_source_audit.json")) or any(output.glob("issue-*/source_attempts/*.json")):
            raise ValueError("Có checkpoint nhưng thiếu context.json; dừng để kiểm tra.")
        else:
            review.save(context_file, provenance)
        summary = summarize(output, plan, provenance)
        if summary["result_count"] != len(plan) and core.model_digest() != audit.DIGEST:
            raise ValueError("Model/digest hiện tại khác lượt trước; chưa gọi sinh AI.")
        try:
            for i, item in enumerate(plan, 1):
                folder = output / item["row"]["artifact_dir"]
                dest = folder / "llm_source_audit.json"
                print(f"[{i}/{len(plan)}] {Path(item['row']['component']).name}", flush=True)
                was_new = not dest.exists()
                if was_new:
                    folder.mkdir(exist_ok=True)
                    for name in ("source.java.txt", "llm_stage1.json", "llm_stage2.json", "cpg_evidence.json"):
                        source_path = item["folder"] / name
                        if source_path.exists():
                            if (folder / name).exists() and (folder / name).read_bytes() != source_path.read_bytes():
                                raise ValueError("Artifact đã lưu bị thay đổi: " + name)
                            shutil.copyfile(source_path, folder / name)
                    review.save(folder / "previous_result.json", item["row"])
                    record = review.ask(item["request"], item["source"], item["stage"]["model_assessment"]["missing_context"],
                        item["row"]["line"], checkpoint=folder / "source_attempts", retry_incomplete=retry_incomplete)
                    review.save(dest, record)
                else:
                    print("    Đã lưu; dùng checkpoint, kể cả lỗi đã lưu.", flush=True)
                row = make_result(item, read(dest))
                summary = summarize(output, plan, provenance)
                print(f"    {item['row']['verdict']} -> {row['verdict']} | lỗi: {row['error_kind']}", flush=True)
                if was_new and row["source_audit_error_kind"] in {"OLLAMA_TIMEOUT", "OLLAMA_HTTP_ERROR", "OLLAMA_ERROR", "CONTEXT_LIMIT", "TRUNCATED_OUTPUT", "INVALID_ENVELOPE"}:
                    print("Dừng sau lỗi dịch vụ/ngân sách để kiểm tra kết quả đã lưu.", flush=True)
                    break
        finally:
            summary = summarize(output, plan, provenance)
            bundle(output)
        print(f"ĐÃ LƯU: {summary['result_count']}/{len(plan)} kết quả; {summary['error_count']} lỗi kiểm tra nguồn.")
        return 0 if summary["state"] == "COMPLETED" and summary["error_count"] == 0 else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-run", type=Path, default=Path(DEFAULT_RUN))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--retry-incomplete", action="store_true")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if Path(__file__).resolve().parent != root:
        raise ValueError("Chạy lệnh từ ~/AI_sec_tool, nơi đã cài gói cập nhật.")
    previous = args.previous_run.resolve()
    plan, provenance = prepare(root, previous)
    output = root / "experiments" / "sql_source_recheck_v1" / (previous.name + "-" + review.fingerprint(provenance)[:12])
    print(f"SOURCE_RECHECK: {len(plan)} cảnh báo SQL; tối đa {len(plan)*review.MAX_CALLS} lượt sinh mới.")
    print("Tái sử dụng bước SQL đã lưu; gọi lại kiểm tra nguồn. Đây là lượt sửa lỗi sau đánh giá.")
    print("KẾT QUẢ:", output)
    if args.check:
        print("SOURCE_RECHECK_OK: hash, mã nguồn và bước SQL khớp; chưa gọi AI/SonarQube/Joern.")
        return 0
    return run(plan, provenance, output, args.retry_incomplete)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Đã dừng. Giữ checkpoint; lượt dở cần --retry-incomplete để gọi lại.")
        sys.exit(130)
    except Exception as exc:
        print("[LỖI] " + str(exc), file=sys.stderr)
        sys.exit(1)
