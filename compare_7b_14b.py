"""Compare the saved 7B answers with 14B using exactly the same six requests.

Run in ~/AI_sec_tool beside check_short_prompt.py and its existing dependencies:
    ollama pull qwen2.5-coder:14b-instruct-q4_K_M
    OLLAMA_TIMEOUT=900 python3 compare_7b_14b.py

Only the model field changes in the generation request. No prompt changes,
answer keys, schema, retries, source edits, scanner, or Joern invocation.
Six new calls; reuse every saved 7B answer. Completed calls are checkpointed.
Plain-language answers require human review; no automatic accuracy score.
"""
import argparse
import copy
import fcntl
import inspect
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import check_short_prompt as short

io = short.previous
EXPERIMENT = "sql89-short-prompt-model-comparison-1"
BASELINE_EXPERIMENT = "sql89-short-prompt-expansion-1"
BASELINE_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
TARGET_MODEL = "qwen2.5-coder:14b-instruct-q4_K_M"
SAMPLES = ("Trial01", "Trial03", "Trial04", "Trial05", "Trial06", "Trial08")
BASELINE = Path("experiments/short_prompt_all_v1") / io.ANALYSIS_ID / "short_prompt_all_results.json"
OUTPUT = Path("experiments/model_14b_v1") / io.ANALYSIS_ID


def prepare_plan(path):
    baseline = io.read_json(path)
    if (baseline.get("experiment") != BASELINE_EXPERIMENT or baseline.get("state") != "COMPLETED"
            or baseline.get("baseline_analysis_id") != io.ANALYSIS_ID or not baseline.get("model_digest")):
        raise ValueError("Cần short_prompt_all_results.json hoàn tất của lượt 7B đã đối chiếu.")
    if sorted(r.get("sample", "") for r in baseline["comparisons"]) != sorted(SAMPLES):
        raise ValueError("Baseline phải có đúng sáu mẫu, không thiếu hoặc trùng.")
    plan = []
    for name in SAMPLES:
        row = next(r for r in baseline["comparisons"] if r["sample"] == name)
        response = row["response"]
        request = response["request_payload"]
        generation = response["generation"]
        if (response.get("error_kind") is not None or generation.get("done") is not True
                or generation.get("done_reason") == "length"
                or not isinstance(response.get("raw_output"), str) or not response["raw_output"].strip()):
            raise ValueError(f"{name} chưa có câu trả lời 7B đầy đủ để so sánh.")
        if (set(request) != {"model", "system", "prompt", "stream", "options"}
                or request["model"] != BASELINE_MODEL or request["stream"] is not False
                or request["options"] != {"temperature": 0, "seed": 42, "num_ctx": 4096, "num_predict": 1024}
                or request["system"] != short.SYSTEM or not request["prompt"].endswith(short.QUESTIONS)
                or io.fingerprint(request) != row["request_sha256"]):
            raise ValueError(f"Request {name} đã khác prompt ngắn/cấu hình 7B đã chốt.")
        source = io.section(request["prompt"], "[MÃ NGUỒN — DỮ LIỆU]\n", "\n[HẾT MÃ NGUỒN]")
        numbered = source.splitlines()
        if not numbered or any(not line.startswith(f"{i}: ") for i, line in enumerate(numbered, 1)):
            raise ValueError(f"Mã nguồn đánh số dòng của {name} không hợp lệ.")
        variant = copy.deepcopy(request)
        variant["model"] = TARGET_MODEL
        plan.append({"sample": name, "issue_id": row["issue_id"], "source_sha256": row["source_sha256"],
                     "baseline_request_sha256": row["request_sha256"],
                     "candidate_request_sha256": io.fingerprint(variant),
                     "request_payload": variant, "baseline_7b": response})
    return baseline, plan


def target_digest():
    base = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
    try:
        response = requests.get(base + "/api/tags", timeout=(5, 15))
        response.raise_for_status()
        matches = [r.get("digest") for r in response.json().get("models", [])
                   if r.get("name") == TARGET_MODEL or r.get("model") == TARGET_MODEL]
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        raise ValueError("Không đọc được danh sách model từ Ollama; chưa gọi AI.") from None
    if len(matches) != 1 or not matches[0]:
        raise ValueError(f"Chưa có đúng model 14B. Chạy: ollama pull {TARGET_MODEL}")
    return matches[0]


def build_summary(output, context, plan):
    rows = []
    for item in plan:
        row = {key: item[key] for key in ("sample", "issue_id", "source_sha256",
               "baseline_request_sha256", "candidate_request_sha256", "baseline_7b")}
        row["candidate_14b"] = None
        path = output / item["sample"] / "llm_result.json"
        if path.exists():
            saved = io.read_json(path)
            meta = saved.get("experiment", {})
            if (saved.get("request_payload") != item["request_payload"] or meta.get("name") != EXPERIMENT
                    or meta.get("sample") != item["sample"] or meta.get("model_digest") != context["candidate_digest"]):
                raise ValueError(f"Checkpoint {item['sample']} thuộc lượt khác; không ghi đè.")
            body = saved.get("ollama_response") or {}
            row["candidate_14b"] = {key: saved[key] for key in (
                "raw_output", "error_kind", "review_status", "elapsed_seconds", "request_payload")}
            row["candidate_14b"]["generation"] = {key: body.get(key) for key in (
                "done", "done_reason", "prompt_eval_count", "eval_count", "load_duration", "eval_duration")}
        rows.append(row)
    done = [r["candidate_14b"] for r in rows if r["candidate_14b"] is not None]
    return {"experiment": EXPERIMENT, "state": "COMPLETED" if len(done) == 6 else "IN_PROGRESS",
            "baseline_model": BASELINE_MODEL, "candidate_model": TARGET_MODEL,
            "baseline_digest": context["baseline_digest"], "candidate_digest": context["candidate_digest"],
            "changed": "Only the model field in each generation request changes.",
            "unchanged": ["source", "issue line", "system", "prompt", "seed", "temperature", "context and output limits", "format omitted"],
            "grading": "Human review of conclusion and explanation separately. No automatic TP/FP or accuracy score.",
            "counts": {"paired_samples": 6, "reused_7b_responses": 6, "saved_14b_calls": len(done),
                       "call_problems": sum(bool(r["error_kind"]) for r in done)},
            "limitations": ["Six development cases; not a held-out benchmark.",
                            "Historical 7B answers reused; no rerun for variance or controlled timing.",
                            "Larger model is not guaranteed to improve these answers.",
                            "This compares model packages, not parameter count as an isolated causal factor."],
            "comparisons": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument("--dry-run", action="store_true", help="Check local inputs only; no writes or network.")
    args = parser.parse_args()
    lock = None
    try:
        baseline_path = args.baseline.resolve()
        baseline, plan = prepare_plan(baseline_path)
        print("Dùng lại sáu câu trả lời 7B; chỉ gọi thêm sáu lượt 14B.", flush=True)
        print("Giữ nguyên prompt và code. Không tự chấm đúng/sai từ trạng thái chạy.", flush=True)
        if args.dry_run:
            print("Dữ liệu hợp lệ. Chưa gọi AI, chưa tạo kết quả.")
            return 0
        output = OUTPUT.resolve()
        if output == baseline_path.parent or output.is_relative_to(baseline_path.parent):
            raise ValueError("Đầu ra phải tách biệt với baseline.")
        output.mkdir(parents=True, exist_ok=True)
        lock = (output / "run.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Lượt so sánh đang chạy ở Terminal khác.") from None
        context_file = output / "experiment.json"
        existing = io.read_json(context_file) if context_file.exists() else None
        if not existing and any((output / name / "llm_result.json").exists() for name in SAMPLES):
            raise ValueError("Có kết quả nhưng thiếu experiment.json; cần đối chiếu lại.")
        context = {"experiment": EXPERIMENT, "baseline_path": str(baseline_path),
                   "baseline_sha256": io.sha(baseline_path.read_bytes()), "baseline_digest": baseline["model_digest"],
                   "candidate_model": TARGET_MODEL,
                   "candidate_digest": existing["candidate_digest"] if existing else target_digest(),
                   "script_sha256": io.sha(Path(__file__).read_bytes()),
                   "helper_hashes": {m.__name__: io.sha(Path(inspect.getfile(m)).read_bytes()) for m in (short, io)},
                   "requests": {p["sample"]: p["candidate_request_sha256"] for p in plan}}
        if existing and existing != context:
            raise ValueError("Baseline hoặc script đã khác lượt đã lưu; không ghi đè.")
        initial = build_summary(output, context, plan)
        if existing and initial["counts"]["saved_14b_calls"] < 6 and target_digest() != context["candidate_digest"]:
            raise ValueError("Model 14B đã đổi digest giữa hai lượt; không trộn kết quả.")
        if not existing:
            io.write_json(context_file, context)
        summary_file = output / "model_comparison.json"
        io.write_json(summary_file, initial)
        for i, item in enumerate(plan, 1):
            folder = output / item["sample"]
            folder.mkdir(exist_ok=True)
            dest = folder / "llm_result.json"
            if dest.exists():
                print(f"[{i}/6] {item['sample']}: đã lưu, bỏ qua.", flush=True)
                continue
            io.write_json(folder / "request.json", item["request_payload"])
            print(f"[{i}/6] Đang hỏi model 14B cho {item['sample']}...", flush=True)
            result = short.ask(item["request_payload"])
            result["experiment"] = {"name": EXPERIMENT, "sample": item["sample"],
                "model_digest": context["candidate_digest"], "saved_at": datetime.now(timezone.utc).isoformat()}
            io.write_json(dest, result)
            io.write_json(summary_file, build_summary(output, context, plan))
            print(f"  {result['review_status']} | {result['elapsed_seconds']} giây | lỗi: {result['error_kind']}", flush=True)
            if result["error_kind"]:
                print("Dừng sau lỗi. Gửi file tổng hợp để kiểm tra; không tự chạy lặp mẫu lỗi.")
                break
        final = build_summary(output, context, plan)
        print(f"Đã lưu {final['counts']['saved_14b_calls']}/6 lượt 14B và dùng lại 6 câu trả lời 7B.")
        print(f"FILE CẦN GỬI: {summary_file}")
        return 0 if final["state"] == "COMPLETED" and not final["counts"]["call_problems"] else 1
    except KeyboardInterrupt:
        print("\nĐã dừng. Chạy lại lệnh sẽ bỏ qua các mẫu đã lưu kết quả.")
        return 130
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            lock.close()


if __name__ == "__main__":
    sys.exit(main())
