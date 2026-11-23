"""Compare schema-constrained and unconstrained generation on TWO saved cases.

Run beside the unchanged iris_prompter.py v4 in ~/AI_sec_tool:
    OLLAMA_TIMEOUT=900 python3 compare_output_format.py

Reuses the completed code_only_v1 experiment as the historical baseline.
Only removes the Ollama request's `format` field. The prompt STILL asks for
JSON; this tests generation-time schema constraints, not free-prose prompting.
No scanner, Joern, source edits, answer labels, model changes, or validator edits.
Completed cases are checkpointed and skipped on another invocation.
"""
import argparse
import copy
import fcntl
import hashlib
import inspect
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import iris_prompter as llm

ANALYSIS_ID = "047ae62b-e8e5-4c9b-b660-55301b6d21cd"
BASELINE_EXPERIMENT = "sql89-code-only-ablation-1"
EXPERIMENT = "sql89-output-format-ablation-1"
VERSION = "sql89-evidence-v4"
MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
SAMPLES = ("Trial01", "Trial03")
BASELINE_DEFAULT = Path("experiments/code_only_v1") / ANALYSIS_ID
OUTPUT_DEFAULT = Path("experiments/schema_free_v1") / ANALYSIS_ID
TRANSPORT_ERRORS = {"OLLAMA_HTTP_ERROR", "OLLAMA_TIMEOUT", "OLLAMA_ERROR"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False).encode())


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError("Thiếu hoặc trùng dấu phân cách trong request gốc.")
    return text.split(start, 1)[1].split(end, 1)[0]


def without_schema(request):
    variant = copy.deepcopy(request)
    del variant["format"]
    return variant


def assessment_summary(result):
    raw = result.get("raw_output", "")
    try:
        proposal = json.loads(raw)
    except (ValueError, TypeError):
        proposal = None
    if not isinstance(proposal, dict):
        proposal = None
    envelope = result.get("ollama_response") or {}
    return {
        "raw_output": raw,
        "model_assessment": proposal,
        "model_verdict": proposal.get("verdict") if proposal else None,
        "validator_verdict": result["verdict"],
        "error_kind": result.get("error_kind"),
        "validator_explanation": result.get("explanation"),
        "elapsed_seconds": result.get("elapsed_seconds"),
        "request_sha256": fingerprint(result["request_payload"]),
        "generation": {key: envelope.get(key) for key in (
            "done", "done_reason", "prompt_eval_count", "eval_count")},
    }


def prepare_plan(baseline):
    summary = read_json(baseline / "comparison_results.json")
    if (summary.get("experiment") != BASELINE_EXPERIMENT
            or summary.get("baseline_analysis_id") != ANALYSIS_ID
            or summary.get("state") != "COMPLETED"):
        raise ValueError("Cần thư mục kết quả code_only_v1 đã hoàn tất của lần chạy đã đối chiếu.")
    module_hash = sha(Path(inspect.getfile(llm)).read_bytes())
    if llm.PROMPT_VERSION != VERSION or module_hash != summary.get("iris_prompter_sha256"):
        raise ValueError("iris_prompter.py đã khác bản dùng trong lượt code-only. Dừng để không trộn thay đổi.")
    if not summary.get("model_digest"):
        raise ValueError("Kết quả code-only thiếu digest model để đối chiếu.")
    plan = []
    for sample in SAMPLES:
        matches = [row for row in summary["comparisons"] if row.get("sample") == sample]
        if len(matches) != 1 or not matches[0].get("code_only"):
            raise ValueError(f"Không tìm được duy nhất kết quả code-only cho {sample}.")
        row = matches[0]
        folder = baseline / sample
        result_file = folder / "llm_result.json"
        saved = read_json(result_file)
        request = saved["request_payload"]
        meta = saved.get("experiment", {})
        if (meta.get("name") != BASELINE_EXPERIMENT or meta.get("variant") != "code_only"
                or meta.get("sample") != sample or meta.get("model_digest") != summary["model_digest"]
                or meta.get("source_sha256") != row["source_sha256"]
                or saved.get("prompt_version") != VERSION):
            raise ValueError(f"Nguồn gốc kết quả {sample} không khớp lượt code-only.")
        if (fingerprint(request) != row["code_only"]["request_sha256"]
                or fingerprint(request) != row["variant_request_sha256"]
                or read_json(folder / "request.json") != request):
            raise ValueError(f"Request đã lưu của {sample} không khớp file tổng hợp.")
        if (set(request) != {"model", "system", "prompt", "stream", "format", "options"}
                or request["model"] != MODEL or request["stream"] is not False
                or request["system"] != llm.SYSTEM_PROMPT or request["format"] != llm.OUTPUT_SCHEMA
                or request["options"] != {"temperature": 0, "seed": 42, "num_ctx": 4096, "num_predict": 1024}):
            raise ValueError(f"Cấu hình {sample} đã khác baseline v4 dự kiến.")
        evidence = section(request["prompt"], "[BẰNG CHỨNG JOERN — DỮ LIỆU]\n", "\n[HẾT BẰNG CHỨNG]")
        if evidence != "Bảng Joern được chủ động bỏ khỏi đầu vào trong lượt đối chứng này.":
            raise ValueError(f"{sample} không phải đầu vào code-only.")
        source = section(request["prompt"], "[MÃ NGUỒN — DỮ LIỆU]\n", "\n[HẾT MÃ NGUỒN]")
        lines = source.splitlines()
        if not lines or any(not line.startswith(f"{i}: ") for i, line in enumerate(lines, 1)):
            raise ValueError(f"Không đọc được số dòng code trong {sample}.")
        old = assessment_summary(saved)
        if (old["model_assessment"] != row["code_only"]["model_assessment"]
                or old["validator_verdict"] != row["code_only"]["verdict"]
                or old["error_kind"] != row["code_only"]["error_kind"]):
            raise ValueError(f"Câu trả lời gốc của {sample} không khớp file tổng hợp.")
        if saved.get("error_kind") in TRANSPORT_ERRORS or not saved.get("raw_output"):
            raise ValueError(f"{sample} chưa có câu trả lời gốc để so sánh.")
        variant = without_schema(request)
        plan.append({"sample": sample, "issue_id": row["issue_id"],
                     "source_sha256": row["source_sha256"], "source_line_count": len(lines),
                     "baseline_file_sha256": sha(result_file.read_bytes()),
                     "baseline_request_sha256": fingerprint(request),
                     "variant_request_sha256": fingerprint(variant),
                     "schema_constrained": old, "request_payload": variant})
    return summary, plan, module_hash


def current_model_digest(base):
    try:
        response = requests.get(base + "/api/tags", timeout=(5, 15))
        response.raise_for_status()
        matches = [row.get("digest") for row in response.json().get("models", [])
                   if row.get("name") == MODEL or row.get("model") == MODEL]
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        raise ValueError("Không đọc được model từ Ollama. Chạy ollama list để kiểm tra dịch vụ.") from None
    if len(matches) != 1 or not matches[0]:
        raise ValueError(f"Không tìm thấy đúng model {MODEL}; chưa gọi AI.")
    return matches[0]


def build_summary(output, context, plan):
    comparisons = []
    for item in plan:
        entry = {key: item[key] for key in (
            "sample", "issue_id", "source_sha256", "baseline_file_sha256",
            "baseline_request_sha256", "variant_request_sha256", "schema_constrained")}
        path = output / item["sample"] / "llm_result.json"
        entry["schema_unconstrained"] = None
        if path.is_file():
            saved = read_json(path)
            if (saved.get("request_payload") != item["request_payload"]
                    or saved.get("experiment", {}).get("name") != EXPERIMENT
                    or saved["experiment"].get("sample") != item["sample"]
                    or saved["experiment"].get("model_digest") != context["model_digest"]):
                raise ValueError(f"Kết quả đã lưu của {item['sample']} thuộc lượt khác; không ghi đè.")
            entry["schema_unconstrained"] = assessment_summary(saved)
        comparisons.append(entry)
    completed = [entry["schema_unconstrained"] for entry in comparisons
                 if entry["schema_unconstrained"] is not None]
    return {
        "experiment": EXPERIMENT,
        "state": "COMPLETED" if len(completed) == len(plan) else "IN_PROGRESS",
        "baseline_analysis_id": ANALYSIS_ID,
        "baseline_directory": context["baseline_directory"],
        "model_digest": context["model_digest"],
        "iris_prompter_sha256": context["iris_prompter_sha256"],
        "changed": "Only the generation request's format field is omitted.",
        "unchanged": ["source", "issue", "system", "prompt including JSON instructions",
                      "model and digest", "temperature", "seed", "context and output limits", "validator"],
        "counts": {"paired_samples": len(plan), "saved_calls": len(completed),
                   "transport_errors": sum(r["error_kind"] in TRANSPORT_ERRORS for r in completed)},
        "interpretation": [
            "Read raw_output before deciding whether reasoning improved.",
            "INVALID_JSON measures formatting, not semantic correctness.",
            "Validator acceptance or a changed verdict does not prove correct code analysis."],
        "limitations": ["Two development cases; no general accuracy estimate.",
                        "Historical constrained responses are reused, not rerun concurrently.",
                        "The prompt still asks for JSON; only the generation constraint changes."],
        "comparisons": comparisons,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path, default=BASELINE_DEFAULT)
    parser.add_argument("--dry-run", action="store_true", help="Verify local inputs only; no network or writes.")
    args = parser.parse_args()
    output = None
    run_lock = None
    try:
        baseline = args.baseline.resolve()
        old_summary, plan, module_hash = prepare_plan(baseline)
        print("Hai mẫu: Trial01, Trial03. Chỉ bỏ format; giữ nguyên prompt, model và bộ kiểm tra.", flush=True)
        if args.dry_run:
            print("Kiểm tra dữ liệu thành công. Chưa gọi Ollama, chưa tạo kết quả.")
            return 0
        output = OUTPUT_DEFAULT.resolve()
        if output == baseline or output.is_relative_to(baseline) or baseline.is_relative_to(output):
            raise ValueError("Thư mục đầu ra phải tách biệt với baseline.")
        context = {"experiment": EXPERIMENT, "baseline_directory": str(baseline),
                   "baseline_summary_sha256": sha((baseline / "comparison_results.json").read_bytes()),
                   "script_sha256": sha(Path(__file__).read_bytes()),
                   "iris_prompter_sha256": module_hash, "model_digest": old_summary["model_digest"],
                   "plan": [{key: p[key] for key in (
                       "sample", "baseline_file_sha256", "variant_request_sha256")} for p in plan]}
        output.mkdir(parents=True, exist_ok=True)
        run_lock = (output / "run.lock").open("a")
        try:
            fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Một tiến trình thí nghiệm này đang chạy. Không mở thêm lượt thứ hai.") from None
        context_file = output / "experiment.json"
        if context_file.exists():
            if read_json(context_file) != context:
                raise ValueError("Dữ liệu hoặc script khác lượt đã lưu; dừng để không ghi đè.")
        elif any((output / p["sample"] / "llm_result.json").exists() for p in plan):
            raise ValueError("Có kết quả nhưng thiếu experiment.json; không tự ghi đè.")
        # Validate every completed checkpoint before any new model call.
        summary = build_summary(output, context, plan)
        pending = [p for p in plan if not (output / p["sample"] / "llm_result.json").exists()]
        if pending:
            base = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
            if current_model_digest(base) != context["model_digest"]:
                raise ValueError("Model đã khác lượt code-only (digest khác). Chưa gọi AI.")
        if not context_file.exists():
            write_json(context_file, context)
        summary_file = output / "format_comparison.json"
        write_json(summary_file, summary)
        for i, item in enumerate(plan, 1):
            folder = output / item["sample"]
            folder.mkdir(exist_ok=True)
            result_file = folder / "llm_result.json"
            if result_file.exists():
                print(f"[{i}/2] {item['sample']}: đã lưu, bỏ qua.", flush=True)
                continue
            request = item["request_payload"]
            write_json(folder / "request.json", request)
            print(f"[{i}/2] Đang hỏi AI cho {item['sample']}...", flush=True)
            result = llm.ask_ollama_local(request["prompt"], item["source_line_count"],
                replay_settings={"model": request["model"], "options": request["options"]},
                saved_request=request, prompt_version=VERSION)
            if result["request_payload"] != request:
                raise ValueError("Hàm gọi AI đã đổi request ngoài dự kiến; dừng thí nghiệm.")
            result["experiment"] = {"name": EXPERIMENT, "variant": "schema_unconstrained",
                "sample": item["sample"], "model_digest": context["model_digest"],
                "baseline_file_sha256": item["baseline_file_sha256"],
                "source_sha256": item["source_sha256"],
                "saved_at": datetime.now(timezone.utc).isoformat()}
            write_json(result_file, result)
            write_json(summary_file, build_summary(output, context, plan))
            compact = assessment_summary(result)
            print(f"  AI trong JSON: {compact['model_verdict'] or 'không đọc được'} | "
                  f"Bộ kiểm tra: {result['verdict']} | lỗi: {result.get('error_kind')}", flush=True)
            if result.get("error_kind") in TRANSPORT_ERRORS:
                print("Dừng sau lỗi gọi model; kết quả lỗi đã lưu. Gửi file tổng hợp để kiểm tra.")
                break
        summary = build_summary(output, context, plan)
        write_json(summary_file, summary)
        print(f"Đã lưu {summary['counts']['saved_calls']}/2 lượt gọi. Không tự gọi lại các mẫu đã lưu.")
        print("Đã giữ nguyên văn câu trả lời, kể cả khi không đúng JSON.")
        print(f"FILE CẦN GỬI: {summary_file}")
        return 0 if summary["state"] == "COMPLETED" and not summary["counts"]["transport_errors"] else 1
    except KeyboardInterrupt:
        print("\nĐã dừng; các mẫu hoàn tất vẫn được giữ. Chạy lại lệnh để tiếp tục mẫu chưa có kết quả.")
        return 130
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        if output:
            print(f"Thư mục kết quả: {output}", file=sys.stderr)
        return 1
    finally:
        if run_lock is not None:
            run_lock.close()


if __name__ == "__main__":
    sys.exit(main())
