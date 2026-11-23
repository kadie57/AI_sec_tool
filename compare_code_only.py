"""One bounded code-only ablation of the saved sql89-evidence-v4 pilot.

Run beside iris_prompter.py and cwe_mapper.py in ~/AI_sec_tool:
    OLLAMA_TIMEOUT=900 python3 compare_code_only.py

Only the text inside the Joern evidence block changes. Original source,
instructions, model name, output schema and generation options are preserved.
Reuses the historical with-CPG results; does NOT rescan or rerun Joern.
Six paired samples only. Trial07 has no historical LLM request; it is reported
as excluded, not silently counted as a model result. Trial02 has no SQL warning.
Each completed request is saved. Repeating the command resumes pending cases,
including after Ctrl+C. It does not automatically retry recorded failed calls.
This small development experiment cannot establish general model accuracy.
"""
import argparse
import copy
import hashlib
import inspect
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import requests
import iris_prompter as llm

EXPERIMENT = "sql89-code-only-ablation-1"
ANALYSIS_ID = "047ae62b-e8e5-4c9b-b660-55301b6d21cd"
VERSION = "sql89-evidence-v4"
MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
PREFIX = "Clean_Code/pilot_sql89/"
PAIRED = ("Trial01", "Trial03", "Trial04", "Trial05", "Trial06", "Trial08")
CPG_START = "[BẰNG CHỨNG JOERN — DỮ LIỆU]\n"
CPG_END = "\n[HẾT BẰNG CHỨNG]"
OMITTED = "Bảng Joern được chủ động bỏ khỏi đầu vào trong lượt đối chứng này."


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return sha_bytes(json.dumps(value, sort_keys=True, ensure_ascii=False).encode())


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError("Dữ liệu thiếu hoặc trùng dấu phân cách; dừng để tránh đổi nhầm prompt.")
    before, rest = text.split(start, 1)
    body, after = rest.split(end, 1)
    return before, body, after


def code_only_payload(original):
    payload = copy.deepcopy(original)
    before, body, after = section(payload["prompt"], CPG_START, CPG_END)
    if not body.strip():
        raise ValueError("Lần chạy gốc không chứa bằng chứng Joern để làm đối chứng.")
    payload["prompt"] = before + CPG_START + OMITTED + CPG_END + after
    return payload


def locate_baseline(runs):
    candidates = []
    for path in runs.glob("*/manifest.json"):
        try:
            manifest = read_json(path)
        except (OSError, ValueError):
            continue
        if manifest.get("analysis_id") == ANALYSIS_ID and manifest.get("state") == "COMPLETED":
            candidates.append(path.parent)
    if len(candidates) != 1:
        raise ValueError("Không tìm được duy nhất lần chạy đã đối chiếu trong runs. "
                         "Dùng --baseline với thư mục gốc chứa ai_results.json của lần đó.")
    return candidates[0].resolve()


def under(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Đường dẫn artifact vượt thư mục lần chạy.")
    return path


def prepare_plan(baseline_dir):
    manifest = read_json(baseline_dir / "manifest.json")
    if (manifest.get("analysis_id") != ANALYSIS_ID or manifest.get("state") != "COMPLETED"
            or manifest.get("collect_only") is not False or manifest.get("prompt_version") != VERSION):
        raise ValueError("Thư mục không phải baseline v4 đã đối chiếu; không tự chọn lần khác.")
    if llm.PROMPT_VERSION != VERSION:
        raise ValueError("Cần giữ iris_prompter.py ở bản v4 cho thí nghiệm này.")
    rows = read_json(baseline_dir / "ai_results.json")
    if not isinstance(rows, list):
        raise ValueError("ai_results.json phải là danh sách.")
    prefix = manifest["project"] + ":" + PREFIX
    selected = {}
    for row in rows:
        if row.get("component", "").startswith(prefix) and row.get("mapping", {}).get("supported"):
            name = Path(row["component"]).stem
            if name in selected:
                raise ValueError(f"Có nhiều cảnh báo SQL cho {name}; cần đối chiếu lại trước khi chạy.")
            selected[name] = row
    if set(selected) != set(PAIRED) | {"Trial07"}:
        raise ValueError("Danh sách cảnh báo SQL không khớp 7 mẫu của baseline.")
    if selected["Trial07"].get("error_kind") != "NO_MATCHING_FLOW":
        raise ValueError("Trạng thái Trial07 đã khác baseline đã đối chiếu.")

    plan = []
    for name in PAIRED:
        row = selected[name]
        artifact = under(baseline_dir, row["artifact_dir"])
        source_file = artifact / "source.java.txt"
        result_file = artifact / "llm_result.json"
        source_bytes = source_file.read_bytes()
        source = source_bytes.decode("utf-8")
        source_hash = sha_bytes(source_bytes)
        rel_source = PREFIX + name + ".java"
        if source_hash != row.get("source_sha256") or source_hash != manifest["source_hashes"].get(rel_source):
            raise ValueError(f"Mã nguồn lưu của {name} không khớp hash baseline.")
        saved = read_json(result_file)
        request = saved["request_payload"]
        if (saved.get("prompt_version") != VERSION or request.get("model") != MODEL
                or request.get("format") != llm.OUTPUT_SCHEMA
                or request.get("system") != llm.SYSTEM_PROMPT
                or request.get("stream") is not False):
            raise ValueError(f"Model, hướng dẫn hoặc schema của {name} không khớp bản v4 hiện tại.")
        # Do not permit saved conversation/history or unrecognized request additions.
        if set(request) != {"model", "system", "prompt", "stream", "format", "options"}:
            raise ValueError(f"Request {name} có trường khác baseline dự kiến.")
        if request["options"] != {"temperature": 0, "seed": 42, "num_ctx": 4096, "num_predict": 1024}:
            raise ValueError(f"Cấu hình sinh của {name} không khớp baseline đã đối chiếu.")
        numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(source.splitlines(), 1))
        _, supplied, _ = section(request["prompt"], "[MÃ NGUỒN — DỮ LIỆU]\n", "\n[HẾT MÃ NGUỒN]")
        if supplied != numbered:
            raise ValueError(f"Code trong request của {name} khác source.java.txt.")
        header = request["prompt"].split("[MÃ NGUỒN — DỮ LIỆU]", 1)[0].splitlines()
        if (f"Mã cảnh báo: {row['issue_id']}" not in header
                or f"Dòng cảnh báo: {row['line']}" not in header):
            raise ValueError(f"Request không thuộc đúng cảnh báo của {name}.")
        proposal = json.loads(saved["raw_output"])
        accepted_or_proposed = (saved["proposed_assessment"] if "proposed_assessment" in saved
                                else {k: saved[k] for k in llm.OUTPUT_SCHEMA["required"]})
        if proposal != accepted_or_proposed:
            raise ValueError(f"Kết quả gốc của {name} không nhất quán với raw_output.")
        new_request = code_only_payload(request)
        plan.append({"sample": name, "issue_id": row["issue_id"], "component": row["component"],
                     "line": row["line"], "source_sha256": source_hash,
                     "source_line_count": len(source.splitlines()), "baseline_file": str(result_file),
                     "baseline_file_sha256": sha_bytes(result_file.read_bytes()),
                     "baseline_request_sha256": fingerprint(request),
                     "variant_request_sha256": fingerprint(new_request),
                     "baseline_model_assessment": proposal,
                     "baseline_verdict": saved["verdict"], "baseline_error_kind": saved["error_kind"],
                     "baseline_elapsed_seconds": saved.get("elapsed_seconds"),
                     "request_payload": new_request})
    return manifest, plan


def model_digest(tags, model):
    matches = [r.get("digest") for r in tags.get("models", [])
               if r.get("name") == model or r.get("model") == model]
    return matches[0] if len(matches) == 1 else None


def assessment_summary(result):
    try:
        proposal = json.loads(result.get("raw_output", ""))
    except (TypeError, ValueError):
        proposal = None
    if not isinstance(proposal, dict):
        proposal = None
    return {"model_assessment": proposal, "verdict": result["verdict"],
            "error_kind": result.get("error_kind"), "explanation": result["explanation"],
            "elapsed_seconds": result.get("elapsed_seconds"),
            "request_sha256": fingerprint(result["request_payload"])}


def raw_verdict(proposal):
    verdict = (proposal or {}).get("verdict")
    return verdict if isinstance(verdict, str) and verdict in llm.VERDICTS else "UNAVAILABLE"


def build_summary(output, context, plan):
    comparisons = []
    for item in plan:
        path = output / item["sample"] / "llm_result.json"
        compact = {k: item[k] for k in ("sample", "issue_id", "source_sha256", "baseline_file_sha256",
                                      "baseline_request_sha256", "variant_request_sha256")}
        compact["with_cpg"] = {"model_assessment": item["baseline_model_assessment"],
                               "verdict": item["baseline_verdict"],
                               "error_kind": item["baseline_error_kind"],
                               "elapsed_seconds": item["baseline_elapsed_seconds"]}
        if path.is_file():
            result = read_json(path)
            if fingerprint(result["request_payload"]) != item["variant_request_sha256"]:
                raise ValueError(f"Kết quả đã lưu của {item['sample']} thuộc request khác.")
            compact["code_only"] = assessment_summary(result)
        else:
            compact["code_only"] = None
        comparisons.append(compact)
    done = [r for r in comparisons if r["code_only"] is not None]
    return {"experiment": EXPERIMENT, "state": "COMPLETED" if len(done) == len(plan) else "IN_PROGRESS",
            "baseline_analysis_id": ANALYSIS_ID, "baseline_directory": context["baseline_directory"],
            "changed": "Only the body of the Joern evidence block is replaced by an omission notice.",
            "unchanged": ["source code", "issue", "system instructions", "other prompt text",
                          "model name", "generation options", "output schema", "validator"],
            "model_digest": context["model_digest"],
            "baseline_digest_verified": context["baseline_digest_verified"],
            "iris_prompter_sha256": context["iris_prompter_sha256"],
            "counts": {"paired_samples": len(plan), "completed_calls": len(done),
                       "final_verdicts_code_only": dict(Counter(r["code_only"]["verdict"] for r in done)),
                       "model_verdicts_code_only": dict(Counter(
                           raw_verdict(r["code_only"]["model_assessment"]) for r in done))},
            "excluded": [{"sample": "Trial02", "reason": "No SQL warning in baseline; not an AI success."},
                         {"sample": "Trial07", "reason": "Baseline skipped LLM because no matching flow; no paired saved request."}],
            "limitations": ["Six development cases only; not a held-out benchmark.",
                            "Historical with-CPG results reused, not rerun concurrently.",
                            "Removing the table also shortens the context; this does not isolate why an answer changes.",
                            "A repeated UNKNOWN or a changed verdict is not, by itself, proof of correctness.",
                            "Baseline model binary cannot be verified if old ollama_models.json has no matching digest."],
            "comparisons": comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=Path, default=Path("runs"))
    parser.add_argument("--baseline", type=Path, help="Exact completed baseline folder, if auto-selection fails.")
    parser.add_argument("--dry-run", action="store_true", help="Read and verify all snapshots; no network and no writes.")
    args = parser.parse_args()
    output = None
    try:
        baseline_dir = args.baseline.resolve() if args.baseline else locate_baseline(args.runs)
        manifest, plan = prepare_plan(baseline_dir)
        print(f"Dữ liệu gốc: {baseline_dir}", flush=True)
        print(f"Model giữ nguyên: {MODEL}; prompt/schema v4; số cặp: {len(plan)}", flush=True)
        print("Chỉ bỏ bảng Joern khỏi request; không sửa code, không quét lại, không gửi đáp án cho AI.", flush=True)
        print("Trial02 không có cảnh báo SQL; Trial07 không có request AI gốc: ghi riêng, không tính vào 6 cặp.", flush=True)
        if args.dry_run:
            print("Kiểm tra dữ liệu thành công. Chưa gọi Ollama, chưa tạo kết quả.")
            return 0
        base = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        try:
            response = requests.get(base + "/api/tags", timeout=(5, 15))
            response.raise_for_status()
            current_digest = model_digest(response.json(), MODEL)
        except (requests.RequestException, ValueError, TypeError):
            raise ValueError("Không đọc được danh sách model từ Ollama. Kiểm tra ollama list; chưa gọi phân tích.") from None
        if not current_digest:
            raise ValueError("Không tìm thấy đúng model 7B trong Ollama; không tự chuyển model.")
        old_tags = baseline_dir / "ollama_models.json"
        old_digest = model_digest(read_json(old_tags), MODEL) if old_tags.is_file() else None
        if old_digest and old_digest != current_digest:
            raise ValueError("Digest model đã thay đổi so với baseline. Dừng để không trộn hai thay đổi.")
        context = {"experiment": EXPERIMENT, "baseline_directory": str(baseline_dir),
                   "baseline_manifest_sha256": sha_bytes((baseline_dir / "manifest.json").read_bytes()),
                   "baseline_summary_sha256": sha_bytes((baseline_dir / "ai_results.json").read_bytes()),
                   "script_sha256": sha_bytes(Path(__file__).read_bytes()),
                   "iris_prompter_sha256": sha_bytes(Path(inspect.getfile(llm)).read_bytes()),
                   "model_digest": current_digest, "baseline_digest_verified": old_digest == current_digest,
                   "plan": [{k: p[k] for k in ("sample", "baseline_file_sha256", "variant_request_sha256")}
                            for p in plan]}
        output = Path.cwd() / "experiments" / "code_only_v1" / ANALYSIS_ID
        output.mkdir(parents=True, exist_ok=True)
        lock = output / "experiment.json"
        if lock.is_file():
            if read_json(lock) != context:
                raise ValueError("Dữ liệu, model hoặc script khác lượt đối chứng đã lưu; không ghi đè kết quả cũ.")
        else:
            write_json(lock, context)
        summary_file = output / "comparison_results.json"
        # Validate all existing checkpoints before making any new requests.
        write_json(summary_file, build_summary(output, context, plan))
        for index, item in enumerate(plan, 1):
            folder = output / item["sample"]
            folder.mkdir(exist_ok=True)
            dest = folder / "llm_result.json"
            if dest.is_file():
                print(f"[{index}/{len(plan)}] {item['sample']}: đã lưu, bỏ qua.", flush=True)
                continue
            request = item["request_payload"]
            print(f"[{index}/{len(plan)}] Đang hỏi AI cho {item['sample']}...", flush=True)
            write_json(folder / "request.json", request)
            result = llm.ask_ollama_local(request["prompt"], item["source_line_count"],
                replay_settings={"model": request["model"], "options": request["options"]},
                saved_request=request, prompt_version=VERSION)
            if result["request_payload"] != request:
                raise ValueError("Hàm gọi model đã sửa request ngoài dự kiến; dừng thí nghiệm.")
            result["experiment"] = {"name": EXPERIMENT, "variant": "code_only",
                "sample": item["sample"], "baseline_file_sha256": item["baseline_file_sha256"],
                "source_sha256": item["source_sha256"], "model_digest": current_digest,
                "saved_at": datetime.now(timezone.utc).isoformat()}
            write_json(dest, result)
            write_json(summary_file, build_summary(output, context, plan))
            proposal = assessment_summary(result)["model_assessment"] or {}
            print(f"  AI: {proposal.get('verdict', 'không có JSON hợp lệ')} | "
                  f"Sau kiểm tra: {result['verdict']} | lỗi: {result.get('error_kind')}", flush=True)
            if result.get("error_kind") in {"OLLAMA_HTTP_ERROR", "OLLAMA_TIMEOUT", "OLLAMA_ERROR"}:
                print("Dừng sau lỗi gọi model để tránh chờ lặp. Kết quả đã lưu; gửi file tổng hợp để kiểm tra.")
                break
        summary = build_summary(output, context, plan)
        write_json(summary_file, summary)
        print(f"Đã lưu {summary['counts']['completed_calls']}/{len(plan)} kết quả.")
        print(f"FILE CẦN GỬI: {summary_file}")
        return 0 if summary["state"] == "COMPLETED" else 1
    except KeyboardInterrupt:
        print("\nĐã dừng. Kết quả các mẫu hoàn tất vẫn giữ nguyên; chạy lại lệnh để tiếp tục.")
        return 130
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        if output:
            print(f"Thư mục kết quả: {output}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
