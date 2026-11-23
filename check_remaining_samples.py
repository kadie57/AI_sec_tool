"""Keep the short prompt frozen; run only Trial04, Trial05, Trial06, Trial08.

Run beside the previous experiment scripts in ~/AI_sec_tool:
    OLLAMA_TIMEOUT=900 python3 check_remaining_samples.py

Reuses Trial01 and Trial03 from short_prompt_results.json without inference.
Reads saved code snapshots; no scanner/Joern/model download/source edits.
Outputs six plain-language answers for human review, not automatic verdicts.
The six cases are development samples, not a held-out accuracy benchmark.
"""
import argparse
import fcntl
import inspect
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import check_short_prompt as short
import compare_code_only as snapshots

io = short.previous
EXPERIMENT = "sql89-short-prompt-expansion-1"
REUSED = ("Trial01", "Trial03")
NEW = ("Trial04", "Trial05", "Trial06", "Trial08")
OUTPUT = Path("experiments/short_prompt_all_v1") / io.ANALYSIS_ID


def prepare_plan(short_dir, code_dir):
    completed = io.read_json(short_dir / "short_prompt_results.json")
    code = io.read_json(code_dir / "comparison_results.json")
    if (completed.get("experiment") != short.EXPERIMENT or completed.get("state") != "COMPLETED"
            or completed.get("baseline_analysis_id") != io.ANALYSIS_ID
            or code.get("experiment") != snapshots.EXPERIMENT or code.get("state") != "COMPLETED"
            or code.get("baseline_analysis_id") != io.ANALYSIS_ID
            or not completed.get("model_digest") or completed["model_digest"] != code.get("model_digest")
            or code.get("iris_prompter_sha256") != io.sha(Path(inspect.getfile(io.llm)).read_bytes())):
        raise ValueError("Các lượt trước không khớp model, phiên bản hoặc chưa hoàn tất.")
    # Reconstruct the exact code-only requests from immutable scan snapshots.
    _, originals = snapshots.prepare_plan(Path(code["baseline_directory"]))
    if tuple(p["sample"] for p in originals) != snapshots.PAIRED:
        raise ValueError("Danh sách mẫu không đúng bộ sáu mẫu đã đối chiếu.")
    if sorted(r.get("sample", "") for r in completed["comparisons"]) != sorted(REUSED):
        raise ValueError("Kết quả prompt ngắn phải có duy nhất Trial01 và Trial03.")
    plan = []
    for item in originals:
        name = item["sample"]
        matches = [r for r in code["comparisons"] if r.get("sample") == name]
        if (len(matches) != 1 or matches[0]["code_only"]["request_sha256"] != item["variant_request_sha256"]
                or matches[0]["source_sha256"] != item["source_sha256"]
                or matches[0]["issue_id"] != item["issue_id"]):
            raise ValueError(f"Request code-only của {name} đã khác snapshot gốc.")
        request = short.short_request(io.without_schema(item["request_payload"]))
        entry = {"sample": name, "issue_id": item["issue_id"], "source_sha256": item["source_sha256"],
                 "request_sha256": io.fingerprint(request), "request_payload": request,
                 "origin": "reused" if name in REUSED else "new", "reused_response": None}
        if name in REUSED:
            old = next(r for r in completed["comparisons"] if r["sample"] == name)
            response = old["short_prompt_response"]
            if (old["source_sha256"] != item["source_sha256"] or old["issue_id"] != item["issue_id"]
                    or old["request_sha256"] != entry["request_sha256"]
                    or response["request_payload"] != request or response.get("error_kind") is not None
                    or response["generation"].get("done") is not True
                    or response["generation"].get("done_reason") == "length"
                    or not isinstance(response.get("raw_output"), str) or not response["raw_output"].strip()):
                raise ValueError(f"{name} không khớp prompt ngắn hiện tại hoặc chưa có câu trả lời đầy đủ.")
            entry["reused_response"] = response
        plan.append(entry)
    return completed, plan


def summary(output, context, plan):
    rows = []
    for item in plan:
        row = {k: item[k] for k in ("sample", "issue_id", "source_sha256", "request_sha256", "origin")}
        row["response"] = item["reused_response"]
        path = output / item["sample"] / "llm_result.json"
        if item["origin"] == "new" and path.exists():
            result = io.read_json(path)
            meta = result.get("experiment", {})
            if (result.get("request_payload") != item["request_payload"] or meta.get("name") != EXPERIMENT
                    or meta.get("sample") != item["sample"] or meta.get("model_digest") != context["model_digest"]):
                raise ValueError(f"Kết quả đã lưu của {item['sample']} thuộc lượt khác; không ghi đè.")
            envelope = result.get("ollama_response") or {}
            row["response"] = {k: result[k] for k in (
                "raw_output", "error_kind", "review_status", "elapsed_seconds", "request_payload")}
            row["response"]["generation"] = {k: envelope.get(k) for k in (
                "done", "done_reason", "prompt_eval_count", "eval_count")}
        rows.append(row)
    done = [r for r in rows if r["response"] is not None]
    new_count = sum(r["origin"] == "new" for r in done)
    return {"experiment": EXPERIMENT, "state": "COMPLETED" if new_count == 4 else "IN_PROGRESS",
            "baseline_analysis_id": io.ANALYSIS_ID, "model_digest": context["model_digest"],
            "prompt_design": "Frozen system text and three questions from check_short_prompt.py.",
            "unchanged": ["source snapshots", "issue lines", "short prompt design", "model and digest", "generation options"],
            "grading": "Human review required for both conclusion and explanation; no automatic verdicts.",
            "counts": {"total_samples": 6, "reused_responses": 2, "saved_new_calls": new_count,
                       "call_problems": sum(bool(r["response"]["error_kind"]) for r in done)},
            "excluded": [{"sample": "Trial02", "reason": "No SQL warning in the baseline."},
                         {"sample": "Trial07", "reason": "No baseline LLM request because no matching Joern flow."}],
            "limitations": ["Development samples; no general accuracy claim.",
                            "Trial01 and Trial03 were used to choose this prompt design; keep that distinction in evaluation.",
                            "Prompt is frozen for four additional cases; outputs are not integrated into the pipeline."],
            "comparisons": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--short-baseline", type=Path, default=short.OUTPUT)
    parser.add_argument("--code-baseline", type=Path, default=io.BASELINE_DEFAULT)
    parser.add_argument("--dry-run", action="store_true", help="Verify saved inputs only; no network or writes.")
    args = parser.parse_args()
    lock = None
    try:
        short_dir, code_dir = args.short_baseline.resolve(), args.code_baseline.resolve()
        completed, plan = prepare_plan(short_dir, code_dir)
        print("Dùng lại Trial01, Trial03. Chỉ gọi AI cho Trial04, Trial05, Trial06, Trial08.", flush=True)
        print("Giữ nguyên ba câu hỏi, model và cấu hình. Kết quả cần đọc để chấm đúng/sai.", flush=True)
        if args.dry_run:
            print("Kiểm tra dữ liệu thành công. Chưa gọi AI, chưa tạo kết quả.")
            return 0
        output = OUTPUT.resolve()
        for baseline in (short_dir, code_dir):
            if output == baseline or output.is_relative_to(baseline) or baseline.is_relative_to(output):
                raise ValueError("Thư mục đầu ra phải tách biệt với dữ liệu gốc.")
        context = {"experiment": EXPERIMENT, "model_digest": completed["model_digest"],
            "short_baseline": str(short_dir), "code_baseline": str(code_dir),
            "short_summary_sha256": io.sha((short_dir / "short_prompt_results.json").read_bytes()),
            "code_summary_sha256": io.sha((code_dir / "comparison_results.json").read_bytes()),
            "script_sha256": io.sha(Path(__file__).read_bytes()),
            "helper_hashes": {m.__name__: io.sha(Path(inspect.getfile(m)).read_bytes()) for m in (short, snapshots, io, io.llm)},
            "requests": {p["sample"]: p["request_sha256"] for p in plan}}
        output.mkdir(parents=True, exist_ok=True)
        lock = (output / "run.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Thí nghiệm đang chạy ở Terminal khác.") from None
        context_file = output / "experiment.json"
        if context_file.exists():
            if io.read_json(context_file) != context:
                raise ValueError("Dữ liệu hoặc script khác lượt đã lưu; không ghi đè.")
        elif any((output / name / "llm_result.json").exists() for name in NEW):
            raise ValueError("Có kết quả nhưng thiếu experiment.json; cần đối chiếu lại.")
        initial = summary(output, context, plan)
        if initial["counts"]["saved_new_calls"] < 4:
            base = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
            if io.current_model_digest(base) != context["model_digest"]:
                raise ValueError("Model đã khác lượt trước; chưa gọi AI.")
        if not context_file.exists():
            io.write_json(context_file, context)
        summary_file = output / "short_prompt_all_results.json"
        io.write_json(summary_file, initial)
        for i, item in enumerate((p for p in plan if p["origin"] == "new"), 1):
            folder = output / item["sample"]
            folder.mkdir(exist_ok=True)
            dest = folder / "llm_result.json"
            if dest.exists():
                print(f"[{i}/4] {item['sample']}: đã lưu, bỏ qua.", flush=True)
                continue
            io.write_json(folder / "request.json", item["request_payload"])
            print(f"[{i}/4] Đang hỏi AI cho {item['sample']}...", flush=True)
            result = short.ask(item["request_payload"])
            result["experiment"] = {"name": EXPERIMENT, "sample": item["sample"],
                "model_digest": context["model_digest"], "saved_at": datetime.now(timezone.utc).isoformat()}
            io.write_json(dest, result)
            io.write_json(summary_file, summary(output, context, plan))
            print(f"  {result['review_status']} | {result['elapsed_seconds']} giây | lỗi: {result['error_kind']}", flush=True)
            if result["error_kind"]:
                print("Dừng sau lỗi. Kết quả đã lưu; gửi file tổng hợp để kiểm tra.")
                break
        final = summary(output, context, plan)
        print(f"Đã lưu {final['counts']['saved_new_calls']}/4 lượt mới và dùng lại 2 câu trả lời trước.")
        print(f"FILE CẦN GỬI: {summary_file}")
        return 0 if final["state"] == "COMPLETED" and not final["counts"]["call_problems"] else 1
    except KeyboardInterrupt:
        print("\nĐã dừng. Chạy lại sẽ bỏ qua các mẫu đã có kết quả.")
        return 130
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            lock.close()


if __name__ == "__main__":
    sys.exit(main())
